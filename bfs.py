import re
from gvgen import GvGen
graph=GvGen()
graph.smart_mode=1
entities=set()
objs={}
f=open("test.dot","r")
l=f.readlines()
edges=[]
nodes=[]
nodes_dict={}
ind=0
maxEndTime=0
graph_edges=[]
#POI event
event="wget;write;file;/home/tarunaygr/Desktop/Software Security/question2/latest.zip;<;https://wordpress.org/latest.zip;9290847188"
for i in range(len(l)-1):
	line=l[i]
	if "->" in line.split(" ")[0]:
		edges.append(line.strip("\n").strip(";"))
	else:
		ind=i
for j in range(4,ind+1):
	nodes.append(l[j].strip("\n").strip().strip(";"))
	nodes_dict[nodes[-1].split(" ")[0]]=nodes[-1].split(" ")[1].split("=")[1].strip("]").strip('"')
components=event.split(';')
#file
# print(nodes_dict)
n1=''
#process
n2=''
edge=''
#find maxEndTime of POI event
if components[4]=="<":
	maxEndTime=int(components[-1])
else:	
	if(re.search("[0-9]*[.]+[0-9]*[.]+[0-9]*[.]+[0-9]*", components[3])):
		file=components[3].split('->')[-1].strip()
	else:
		file=components[3].strip()
	process=components[0]
	for i in nodes:
		r=i.split('[')[1].split('=')[1].strip(']').strip('"')
		#print("r",r)
		if r==file:
			n1=i.split(" ")[0]
	for i in nodes:
		r=i.split('[')[1].split('=')[1].strip(']').strip('"')
		if r==process:
			n2=i.split(" ")[0]
	if components[1]=="read":
		edge=n1+"->"+n2
	if components[1]=="write":
		edge=n2+"->"+n1
		#print("*",edge)
	for e in edges:
		#edge start time
		t=e.split(" ")[1].split(",")[-1].split(";")[1].strip()
		if e.split(" ")[0]==edge and int(t)==int(components[6].strip()):
			#print(e)
			maxEndTime=int(e.split(" ")[1].split(",")[-1].split(";")[-1].strip(']').strip('"'))
			break
"""print(file,process)
print(n1)
print(n2)
print(maxEndTime)"""
temp=[]
p=''
x=list(nodes_dict.keys())[list(nodes_dict.values()).index(components[0])]
y=[]
#BFS
visited=[]
queue=[]
queue.append(x)
visited.append(x)
while(queue!=[]):
	s=queue.pop(0)	
	for e in edges:
		if (e.split(" ")[0].split("->")[1].strip()==s) and (int(e.split(" ")[1].split(",")[-1].split(";")[1].strip())<=maxEndTime):
			if e.split(" ")[0].split("->")[0].strip() not in visited:
				queue.append(nodes_dict[e.split(" ")[0].split("->")[0]])
				visited.append(e.split(" ")[0].split("->")[0].strip())
				temp.append(nodes_dict[e.split(" ")[0].split("->")[0]])
				temp.append(nodes_dict[e.split(" ")[0].split("->")[1]])
				y=e.split(" ")[1].split(",")[-1].split("=")[-1].strip(']').strip('"').split(';')
				p=p+y[0]+';'+y[1]+';'+y[2]
				temp.append(p)
				p=''
				graph_edges.append(temp)
				temp=[]
#BFS graph
for l in graph_edges:
	if(l[0] not in entities):
		entities.add(l[0])
		i1=graph.newItem(l[0])
		objs[l[0]]=i1
	else:
		i1=objs[l[0]]
	if(l[1] not in entities):
		entities.add(l[1])
		i2=graph.newItem(l[1])
		objs[l[1]]=i2
	else:
		i2=objs[l[1]]
	link=graph.newLink(i1,i2)
	graph.propertyAppend(link, "label",l[2])
if(components[0] not in entities):
	entities.add(components[0])
	i1=graph.newItem(components[0])
	objs[components[0]]=i1
else:
	i1=objs[components[0]]
if(components[3] not in entities):
	entities.add(components[3])
	i2=graph.newItem(components[3])
	objs[components[3]]=i2
else:
	i2=objs[components[3]]
link=graph.newLink(i1,i2)
s=components[1]+';maxEndTime='+str(maxEndTime)
graph.propertyAppend(link, "label",s)
graph.dot()

		
	
		


