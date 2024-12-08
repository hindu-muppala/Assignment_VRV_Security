
# defining data structures to use
import heapq
import csv

class trieHashmap:

     def __init__(self, val=None, parent=None):
        self.val = val  
        self.parent = parent 
        self.next = {} 

class lastnode(trieHashmap): #last node which has count variable

    def __init__(self, val=None, parent=None):
        super().__init__(val, parent)
        self.count = 1
    
    def __lt__(self, other):
        # Compare nodes by their count attribute ( descending counter )
        return self.count > other.count

    def __repr__(self):
        return f"Node(name={self.val}, count={self.count})"
    
main = trieHashmap()

def add(main, ip_address):

    ip_node = list(map(int, ip_address.split('.')))
    # this ip_node have the value
    node_ = main

    for i in range(0,3):

        if ip_node[i] in node_.next.keys() :
            node_ =  node_.next[ip_node[i]]
        else:
            node_.next[ip_node[i]] = trieHashmap(ip_node[i], node_)
            node_ = node_.next[ip_node[i]]

    # for first three nodes
    # for last node
 
    if ip_node[3] in node_.next.keys() :
        node_.next[ip_node[3]].count += 1   # increase the count     
    else:
        node_.next[ip_node[3]] = lastnode(ip_node[3], node_)


def sort(main, output_file_path):

    heap = []

    def traverse(node):
        ip_address= [str(node.val)]
        for i in range(0, 3):
            node = node.parent
            ip_address.append(str(node.val))
        
        ip_address.reverse()
        return ".".join(ip_address)

    def addInnerHeaps(i, node_):
        if i == 3:
            #node_ has entire new hashmap
            for node in node_.next.values():
                heapq.heappush(heap, node)

        for node in node_.next.values():
            addInnerHeaps(i+1, node)

    # create the file, if not exit, if exits open the file and write
    addInnerHeaps(0, main)
    with open( output_file_path, 'w', newline='') as log_analysis_file:
        print()
        writer = csv.writer(log_analysis_file, delimiter=",")
        writer.writerow(["IP Address", "Request Count"])
        print(f"{'IP Address':<20}{'Request Count'}")
        while len(heap) > 0:
            node_ = heapq.heappop(heap)
            ip_address_ = traverse(node_)
            print(f"{ip_address_:<20}{node_.count}")
            writer.writerow([ip_address_, node_.count])
            
           






        



    





    








          
 

