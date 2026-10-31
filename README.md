# System Call Analysis and Information Flow Tracking

A software security project developed using **Python, Sysdig, and Graphviz** to analyze system-call activity, reconstruct information flow between processes and files, and trace events backward to identify their potential origins.

The system captures Linux system-call events, converts them into structured records, generates directed information-flow graphs, and performs timestamp-aware backward traversal to investigate the events and resources associated with a selected point of interest.

## Overview

Understanding how information moves between processes and files is important for investigating suspicious activity and analyzing system behavior.

This project implements a three-stage workflow:

1. **System Call Parsing:** Capture and parse Sysdig logs to extract process names, operations, file paths, and timestamps.
2. **Information Flow Graph Construction:** Build a directed graph representing interactions between processes and files.
3. **Backward Information Flow Tracking:** Perform timestamp-aware backward traversal from a selected point of interest to identify relevant preceding events.

The resulting graphs are generated in DOT format and visualized using Graphviz.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Log parsing, graph generation, and backward traversal |
| Sysdig | Capturing Linux system-call activity |
| Graphviz | Generating and visualizing information-flow graphs |
| DOT | Representing directed graphs |
| Linux | System-call monitoring environment |
| Breadth-First Search (BFS) | Backward traversal of information-flow relationships |

## System Architecture

```text
                Linux System Activity
                  (wget, cp, execve)
                          |
                          v
                    Sysdig Capture
                          |
                          v
                     capture.txt
                          |
                          v
                      parser.py
                          |
               +----------+----------+
               |                     |
               v                     v
           tuples.txt            output.dot
               |                     |
               |                     v
               |              Graphviz Rendering
               |                     |
               |                     v
               |                output.svg
               |                     
               +---- Information Flow Graph
                                     |
                                     v
                                   bfs.py
                                     |
                                     v
                                  bfs.dot
                                     |
                                     v
                             Graphviz Rendering
                                     |
                                     v
                                  bfs.svg
```

## Key Features

### 1. System Call Monitoring Using Sysdig

The project uses Sysdig to capture selected Linux system calls associated with process execution and file operations.

The monitored operations include:

- `execve` — Process execution
- `read` and `readv` — File read operations
- `write` and `writev` — File write operations

Read and write events are filtered for the `wget` and `cp` processes, while `execve` events are also captured.

Each log entry contains information such as the process name, event type, event category, file descriptor name, event direction, process arguments, and timestamps.

### 2. System Call Log Parsing

The Python parser processes the captured Sysdig logs and extracts structured information describing interactions between processes and resources.

The parsed records follow the format:

```text
<process, operation, object>
```

For example, a parsed record identifies the process performing an operation and the file or resource involved.

The extracted tuples are written to `tuples.txt` for further analysis.

### 3. Information Flow Graph Construction

The parsed system-call events are used to construct a directed information-flow graph.

Graph edges represent interactions between processes and resources.

The direction of each edge depends on the operation:

| Operation | Information flow direction |
|---|---|
| Read | File → Process |
| Write | Process → File |
| execve | Calling process → Executed process |

Each edge includes:

- System-call operation
- Start timestamp
- End timestamp

Edge thickness increases with the number of calls represented by that relationship.

The resulting graph is exported in DOT format and rendered using Graphviz.

### 4. Timestamp-Aware Backward Information Flow Tracking

The project implements a backward traversal algorithm to identify the events and resources associated with a selected point of interest (POI).

Instead of displaying every recorded interaction, the algorithm follows incoming information-flow edges backward while applying timestamp constraints.

The traversal uses breadth-first search and considers whether an event could have contributed information to the selected point of interest.

This produces a smaller graph containing the relevant preceding interactions.

### 5. Graph Visualization

Graphviz is used to generate SVG visualizations for both the complete information-flow graph and the backward traversal results.

The visualizations make it easier to examine:

- Relationships between processes and files
- Read and write operations
- Process execution events
- Event timestamps
- Frequently occurring interactions
- Information-flow paths leading to a selected event

## Project Components

The main scripts and output files are:

```text
.
├── traffic_gen.py
├── parser.py
├── bfs.py
├── capture.txt
├── tuples.txt
├── output.dot
├── output.svg
├── bfs.dot
├── bfs.svg
└── README.md
```

The generated files are created during execution and may not be included in the repository.

### traffic_gen.py

Generates system activity using commands such as `wget` and `cp`.

The resulting system calls can be captured using Sysdig to produce input data for the parser.

### parser.py

Processes Sysdig logs and extracts system-call information.

It supports generating structured tuples and DOT graph output for visualization.

### bfs.py

Performs timestamp-aware backward traversal on the information-flow graph.

Starting from a selected point of interest, the script identifies relevant preceding interactions and produces a reduced graph in DOT format.

## Installation and Setup

### Prerequisites

- Linux environment
- Python 3
- Sysdig
- Graphviz
- Permissions to capture system-call events

Verify the installations:

```bash
python3 --version
sysdig --version
dot -V
```

## Running the Project

### Step 1: Capture System Calls

Run Sysdig with the following filter to capture process execution and selected file operations:

```bash
sudo sysdig \
  '(evt.type=execve and evt.dir=<) or ((evt.type=read or evt.type=readv or evt.type=write or evt.type=writev) and (proc.name=wget or proc.name=cp))' \
  -p '*%proc.name;%evt.type;%evt.category;%fd.name;%evt.dir;%proc.args;%evt.time;%evt.reltime' \
  > capture.txt
```

Keep Sysdig running while generating the test activity.

### Step 2: Generate System Activity

In a separate terminal, run:

```bash
python3 traffic_gen.py
```

The script generates system activity involving `wget` and `cp`, which Sysdig captures.

Stop the Sysdig capture after the required activity has completed.

### Step 3: Parse the Captured Logs

Run the parser to extract structured records:

```bash
python3 parser.py
```

The parser processes `capture.txt` and produces the structured tuples in `tuples.txt`.

### Step 4: Generate the Information Flow Graph

Run the parser in graph-generation mode as described in the project report:

```bash
python3 parser.py > output.dot
```

Render the DOT file as an SVG:

```bash
dot -Tsvg output.dot > output.svg
```

Open `output.svg` to inspect the directed information-flow graph.

### Step 5: Perform Backward Information Flow Tracking

Run the backward traversal script:

```bash
python3 bfs.py > bfs.dot
```

Render the resulting graph:

```bash
dot -Tsvg bfs.dot > bfs.svg
```

The resulting visualization shows the subset of events identified by the backward traversal algorithm.

## Backward Traversal Algorithm

The backward traversal uses timestamps to determine which incoming edges are relevant to the selected point of interest.

The process is:

1. Select a point of interest in the information-flow graph.
2. Determine the maximum end timestamp among its incoming edges.
3. Examine incoming edges and include those whose start timestamps are earlier than the calculated maximum end timestamp.
4. Continue traversing backward through eligible incoming edges.
5. Repeat until no additional qualifying edges are found.
6. Export the resulting subgraph in DOT format.

The algorithm combines graph direction and event timing to narrow the set of potentially relevant interactions.

## Testing and Evaluation

The project was tested using system-call activity generated by `wget` and `cp`.

### Test 1: Log Parsing

Sysdig captured the selected system-call events, and the parser converted the captured records into structured tuples.

The generated tuples were used to identify processes, operations, and accessed resources.

### Test 2: Information Flow Graph Generation

The parsed records were converted into a directed graph.

The resulting visualization displayed:

- Read operations from files to processes
- Write operations from processes to files
- Process execution relationships
- Edge labels containing operations and timestamps
- Thicker edges for relationships with more calls

### Test 3: Backward Information Flow Tracking

A `wget` event was selected as the point of interest.

The backward traversal produced a smaller graph containing interactions relevant to the selected `wget` activity.

The resulting graph excluded unrelated `cp` operations and process execution events not associated with the selected activity.

This made the information-flow graph easier to inspect and interpret.

## Project Outcome

This project demonstrates how system-call monitoring and graph-based analysis can be combined to investigate information flow in Linux environments.

The implementation covers:

- Capturing Linux system calls using Sysdig.
- Parsing raw system-call logs with Python.
- Representing process and file interactions as directed graphs.
- Visualizing information flow using Graphviz.
- Applying timestamp constraints to backward graph traversal.
- Isolating relevant events from larger system activity traces.

The project provides a foundation for understanding system behavior, investigating event dependencies, and analyzing information flow in software security applications.

## Technologies Used

`Python` · `Sysdig` · `Graphviz` · `Linux` · `System Calls` · `Information Flow Tracking` · `Breadth-First Search` · `Graph Analysis`
