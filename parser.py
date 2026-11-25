# Install Sysdig and Graphviz on Ubuntu:
# sudo apt update
# sudo apt install sysdig graphviz

# Install the Python GvGen library:
# python3 -m pip install gvgen

# Run the following command in the same directory to generate
# the Sysdig log file.
#
# sudo sysdig -j \
# '(evt.type=execve or evt.type=fork or evt.type=vfork or evt.type=clone) or ((evt.type=read or evt.type=write or evt.type=readv or evt.type=writev or evt.type=sendto or evt.type=recvfrom or evt.type=sendmsg or evt.type=recvmsg) and (proc.name=wget or proc.name=cp))' \
# -p '*%proc.name %proc.pid %thread.tid %proc.ppid %evt.type %evt.category %fd.type %fd.name %evt.dir %evt.reltime %evt.rawres %fd.sip %fd.sport %fd.dip %fd.dport %fd.l4proto %proc.exepath %proc.args' \
# > capture.txt

# While Sysdig is running, execute traffic_gen.py in another terminal: python3 traffic_gen.py

# Stop Sysdig using Ctrl+C after the workload finishes.

# Run this parser to generate tuples.txt and written.dot: python3 parser.py > written.dot

# Convert the DOT graph into an SVG image: dot -Tsvg written.dot -o written.svg

# Alternatively, generate a PNG image: dot -Tpng written.dot -o written.png

# Open the generated image: xdg-open written.svg

# This parser considers read/write and network data transfer operations performed by wget and cp. It also considers process creation and execution events.
#
# Every successfully processed operation is represented as: <subject, operation, object>
#
# Processes are identified using PID and process name.
# Files are identified using their full paths.
# Network connections are identified using their five-tuples.
#
# Graph nodes represent system entities.
# Graph edges represent individual information flow events.
# Each edge contains its operation, start time, and end time.

import json
import sys
from gvgen import GvGen

# Initialize the information flow graph.
graph = GvGen()
# Disable smart mode to preserve multiple events between the same pair of nodes.
graph.smart_mode = 0
# Store unique entities and their corresponding graph nodes.
objs = {}
# Store system call entry events until their exit events arrive.
pending = {}
# Store completed events.
events = []
# Operations that transfer information into a process.
READ_OPERATIONS = {"read","readv","recvfrom","recvmsg"}
# Operations that transfer information out of a process.
WRITE_OPERATIONS = {"write","writev","sendto","sendmsg"}
# Operations associated with process creation.
PROCESS_OPERATIONS = {"fork","vfork","clone"}
IO_OPERATIONS = READ_OPERATIONS | WRITE_OPERATIONS
SUPPORTED_OPERATIONS = (IO_OPERATIONS |PROCESS_OPERATIONS |{"execve"})
# Check whether a Sysdig field contains a valid value.
def is_valid(value):
    return (value is not None and str(value).strip() not in ("", "<NA>", "N/A"))
# Extract a field from a Sysdig JSON event.
def get_field(event, field):
    fields = event.get("output_fields", event)
    return fields.get(field)
# Convert a field to an integer.
def to_int(value):
    if not is_valid(value):
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
# Construct a unique process identifier using the process name and PID.
def get_process_id(event):
    name = get_field(event, "proc.name")
    pid = to_int(get_field(event, "proc.pid"))
    if not is_valid(name) or pid is None:
        return None
    return ("process", str(name), pid)
# Construct a unique object identifier. An object can be a file or a network connection.
def get_object_id(entry, exit_event):
    # Prefer resource information from the exit event. Some fields may not be available during entry.
    def resource_field(field):
        value = get_field(exit_event, field)
        if is_valid(value):
            return value
        return get_field(entry, field)
    fd_type = resource_field("fd.type")
    fd_name = resource_field("fd.name")
    # Network connection.
    if fd_type in ("ipv4", "ipv6"):
        source_ip = resource_field("fd.sip")
        source_port = to_int(resource_field("fd.sport"))
        destination_ip = resource_field("fd.dip")
        destination_port = to_int(resource_field("fd.dport"))
        protocol = resource_field("fd.l4proto")
        fields = (source_ip,source_port,destination_ip,destination_port,protocol)
        # Do not create incomplete network identifiers.
        if not all(is_valid(value) for value in fields):
            return None
        return ("network",str(source_ip),source_port,str(destination_ip),destination_port,str(protocol))
    # Regular file.
    if fd_type in ("file", "file_v2"):
        if not is_valid(fd_name):
            return None
        return ("file", str(fd_name))
    # Other resources such as pipes, terminals and Unix sockets are outside the scope of this project.
    return None
# Generate a readable label for each graph entity.
def get_entity_label(entity):
    entity_type = entity[0]
    if entity_type == "process":
        name = entity[1]
        pid = entity[2]
        return f"{name} (PID={pid})"
    elif entity_type == "file":
        return entity[1]
    elif entity_type == "network":
        _, sip, sport, dip, dport, protocol = entity
        return (f"[{sip}]:{sport}->" f"[{dip}]:{dport} ({protocol})")
    return str(entity)
# Create a graph node if the entity does not already exist. Otherwise, return its existing graph node.
def get_or_create_node(entity):
    if entity not in objs:
        label = get_entity_label(entity)
        node = graph.newItem(label)
        objs[entity] = node
        # Assign different shapes to different entity types.
        if entity[0] == "process":
            graph.propertyAppend(node,"shape","ellipse")
        elif entity[0] == "file":
            graph.propertyAppend(node,"shape","box")
        elif entity[0] == "network":
            graph.propertyAppend(node,"shape","diamond")
    return objs[entity]
# Construct a completed event and add it to the graph.
def add_event(subject,operation,obj,start_time,end_time,tuples_file):
    if subject is None or obj is None:
        return
    if start_time is None or end_time is None:
        return
    if end_time < start_time:
        return
    # Generate the subject-operation-object tuple.
    subject_label = get_entity_label(subject)
    object_label = get_entity_label(obj)
    item = (f"<{subject_label},"f"{operation},"f"'{object_label}'>")
    tuples_file.write(item + "\n")
    # Store the completed event with its timestamps.
    events.append({"id": len(events),"subject": subject,"operation": operation,"object": obj,"start_time": start_time,"end_time": end_time})
    # Create or retrieve the corresponding graph nodes.
    subject_node = get_or_create_node(subject)
    object_node = get_or_create_node(obj)
    # Assign the direction of information flow.
    if operation in READ_OPERATIONS:
        # Object -> Process
        source = object_node
        destination = subject_node
    elif operation in WRITE_OPERATIONS:
        # Process -> Object
        source = subject_node
        destination = object_node
    elif operation == "execve":
        # Executable file -> Process
        source = object_node
        destination = subject_node
    elif operation in PROCESS_OPERATIONS:
        # Parent process -> Child process
        source = subject_node
        destination = object_node
    else:
        return
    # Create a separate edge for every completed event.
    link = graph.newLink(source, destination)
    # Store the operation, start time and end time. These timestamps are required for backtracking.
    label = f"{operation};{start_time};{end_time}"
    graph.propertyAppend(link, "label", label)
# Process a completed read, write, send or receive operation.
def process_io_event(entry,exit_event,operation,start_time,end_time,tuples_file):
    result = to_int(get_field(exit_event, "evt.rawres"))
    # A negative return value indicates failure.
    # A zero return value indicates no bytes transferred.
    if result is None or result <= 0:
        return
    subject = get_process_id(entry)
    if subject is None:
        subject = get_process_id(exit_event)
    obj = get_object_id(entry, exit_event)
    add_event(subject,operation,obj,start_time,end_time,tuples_file)
# Process a successful execve operation.
def process_exec_event(entry,exit_event,start_time,end_time,tuples_file):
    result = to_int(get_field(exit_event, "evt.rawres"))
    # Ignore failed execve operations.
    if result is None or result != 0:
        return
    # After execve, the process name may have changed. Therefore, use the process information from the exit event.
    subject = get_process_id(exit_event)
    executable = get_field(exit_event,"proc.exepath")
    if not is_valid(executable):
        return
    obj = ("file",str(executable))
    # Information flows from the executable file into the new process image.
    add_event(subject,"execve",obj,start_time,end_time,tuples_file)
# Process a successful process creation operation.
def process_creation_event(entry,exit_event,operation,start_time,end_time,tuples_file):
    child_pid = to_int(get_field(exit_event, "evt.rawres"))
    # On the parent's successful return, the result contains the child PID or task ID. Ignore failed operations and child-side returns.
    if child_pid is None or child_pid <= 0:
        return
    parent = get_process_id(entry)
    if parent is None:
        return
    # A newly forked process initially inherits its parent's process name.
    child = ("process",parent[1],child_pid)
    # Information flows from the parent to the child.
    add_event(parent,operation,child,start_time,end_time,tuples_file)
# Parse the Sysdig log file line by line.
with open("capture.txt", "r", encoding="utf-8") as capture_file, open("tuples.txt", "w", encoding="utf-8") as tuples_file:
    for line_number, line in enumerate(capture_file, start=1):
        line = line.strip()
        # Ignore empty lines.
        if not line:
            continue
        # Parse the JSON-formatted Sysdig event.
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            print(f"Invalid JSON at line {line_number}",file=sys.stderr)
            continue
        # Extract the system call type, thread ID, event direction and relative timestamp.
        operation = get_field(event,"evt.type")
        tid = to_int(get_field(event,"thread.tid"))
        direction = get_field(event,"evt.dir")
        timestamp = to_int(get_field(event,"evt.reltime"))
        # Ignore unsupported or incomplete events.
        if operation not in SUPPORTED_OPERATIONS:
            continue
        if tid is None or timestamp is None:
            continue
        # Identify a pending system call using the thread ID and system call type.
        key = (tid,operation)
        # System call entry event.
        if direction == ">":
            pending[key] = event
        # System call exit event.
        elif direction == "<":
            # Retrieve and remove the corresponding entry.
            entry = pending.pop(key, None)
            # Ignore exit events without a matching entry.
            if entry is None:
                continue
            start_time = to_int(get_field(entry, "evt.reltime"))
            end_time = timestamp
            # Process read/write/send/receive operations.
            if operation in IO_OPERATIONS:
                process_io_event(entry,event,operation,start_time,end_time,tuples_file)
            # Process execution events.
            elif operation == "execve":
                process_exec_event(entry,event,start_time,end_time,tuples_file)
            # Process creation events.
            elif operation in PROCESS_OPERATIONS:
                process_creation_event(entry,event,operation,start_time,end_time,tuples_file)
# Save the completed events in JSON format. The backtracking algorithm can read this file directly instead of parsing the DOT graph again.
with open("events.json", "w", encoding="utf-8") as events_file:
    json.dump(events, events_file, indent=4)
# Print statistics to stderr so that they do not interfere with the DOT output redirected to written.dot.
print(f"Total completed events: {len(events)}",file=sys.stderr)
print(f"Total unique entities: {len(objs)}",file=sys.stderr)
print(f"Unmatched entry events: {len(pending)}",file=sys.stderr)
# Output the information flow graph in DOT format.
graph.dot()
