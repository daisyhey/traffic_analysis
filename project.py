import gc                                           
import sys
from prettytable import PrettyTable       

gc.collect()            
file1 = open("dec-pkt-1.tcp", 'r')                 ##Opening file into read format
readfile= file1.read()                                                   
file1.close()

splitfile=readfile.split('\n')                     ##Spliting file into list                                     
totalPackets = len(splitfile)

totalpayload = 0
windowscounter = 0
windowsbitrate = []
windowsbytesuntilnow = 0
totalfile = []
counter = 0
windowendtime = 299.00
windowpacketcounter = 0
packetpercent = [0, 0, 0, 0, 0, 0]

ipdictionary = {}
portdictionary = {}
new_port_dictionary = {}


p1flag = True
p2flag = False
p3flag = False
p4flag = False

p1_packet_bytes = 0
p2_packet_bytes = 0
p3_packet_bytes = 0
p4_packet_bytes = 0

p1_packets = 0
p2_packets = 0
p3_packets = 0
p4_packets = 0

p1_bitrate = []
p2_bitrate = []
p3_bitrate = []
p4_bitrate = []

port1_bytes = 0
port2_bytes = 0
port3_bytes = 0
port4_bytes = 0

port1_bytes_untilnow = 0
port2_bytes_untilnow = 0
port3_bytes_untilnow = 0
port4_bytes_untilnow = 0

port1_packets = 0
port2_packets = 0
port3_packets = 0
port4_packets = 0



port1_bitrate = []
port2_bitrate = []
port3_bitrate = []
port4_bitrate = []

maxdiff = []
port_maxdiff = []

## Function to calculate percentage based on number of packets
def percent(packetsize):
    if packetsize == 0:
        packetpercent[0]+=1
    elif packetsize >=1 and packetsize <=127:
        packetpercent[1]+=1
    elif packetsize >=128 and packetsize <=255:
        packetpercent[2]+=1
    elif packetsize >=256 and packetsize <=383:
        packetpercent[3]+=1
    elif packetsize >=384 and packetsize <=511:
        packetpercent[4]+=1    
    else:
        packetpercent[5]+=1

## Function to Calculte traffic bytes passing through the same source IP address
def ippackets(sourceip, packetsize):
    try:
        ipdetails = ipdictionary[sourceip]           ##Checking whether IP address has already been encountered
        ipdetails[0]+=1
        ipdetails[1]+=packetsize + 40                ## Adding packet size to total number of byte for this IP address
        ipdictionary[sourceip] = ipdetails
    except:
        ipdictionary[sourceip] = [0, packetsize+40]  ## Adding new IP address to dictonary

def portpackets(destinationport, packetsize):
    try:
        portdetails = portdictionary[destinationport]  ##Checking whether IP port has already been encountered
        portdetails[0]+= 1
        portdetails[1]+=packetsize + 40                ## Adding packet size to total number of byte for this IP address
        portdictionary[destinationport] = portdetails
    except:
        portdictionary[destinationport] = [0 , packetsize+40]  ## Adding new IP address to dictonary

## Function to perform load balancing without causing out-of-order delivery
def addpacket(packetsize, destinationport):
    global port1_bytes              ##  ##  ##  ##  ##  ##  ##  ##   ##
    global port2_bytes              ##                               ##
    global port3_bytes              ##                               ##
    global port4_bytes              ##                               ##

    global port1_packets            ##                               ##
    global port2_packets            ##  Accessing global variables   ##
    global port3_packets            ##                               ##
    global port4_packets            ##                               ##
 
    global port1_bytes_untilnow     ##                               ##
    global port2_bytes_untilnow     ##                               ##
    global port3_bytes_untilnow     ##                               ##
    global port4_bytes_untilnow     ##                               ## 

    global new_port_dictionary      ##  ##  ##  ##  ##  ##  ##  ##   ##
    
    try:        
        port = new_port_dictionary[destinationport]    ##Checking whether the combination of (destionation IP, Destination port and Source IP, Source port) has occured before     
        if port == 1:                                  ## If this combiantion associated with bucket 1
            port1_bytes+=packetsize + 40               ## we increase bytes through packet 1
            port1_bytes_untilnow+=packetsize + 40
                        
        elif port == 2:
            port2_bytes+=packetsize + 40              ## we increase bytes through packet 1        
            port2_bytes_untilnow+=packetsize + 40
                      
        elif port == 3:
            port3_bytes+=packetsize + 40              ## we increase bytes through packet 1
            port3_bytes_untilnow+=packetsize + 40
                       
        elif port == 4:
            port4_bytes+=packetsize + 40              ## we increase bytes through packet 1
            port4_bytes_untilnow+=packetsize + 40
                           
    except:
        if port1_bytes_untilnow <= port2_bytes_untilnow and port1_bytes_untilnow <= port3_bytes_untilnow and port1_bytes_untilnow <= port4_bytes_untilnow :
                                                     ## Find bucket with least number of bytes
            port1_bytes+=packetsize + 40             ## Increasing bytes through this bucket
            port1_bytes_untilnow+=packetsize + 40      
           
            new_port_dictionary[destinationport] = 1  ## Adding Port to dictonary 
        elif port2_bytes_untilnow <= port1_bytes_untilnow and port2_bytes_untilnow <= port3_bytes_untilnow and port2_bytes_untilnow <= port4_bytes_untilnow : ## Find bucket with least number of bytes
            port2_bytes+=packetsize + 40              ## Increasing bytes through this bucket
            port2_bytes_untilnow+=packetsize + 40
  
            new_port_dictionary[destinationport] = 2  ## Adding Port to dictonary
        elif port3_bytes_untilnow <= port2_bytes_untilnow and port3_bytes_untilnow <= port1_bytes_untilnow and port3_bytes_untilnow <= port4_bytes_untilnow :  ## Find bucket with least number of bytes
            port3_bytes+=packetsize + 40              ## Increasing bytes through this bucket
            port3_bytes_untilnow+=packetsize + 40

            new_port_dictionary[destinationport] = 3   ## Adding Port to dictonary
        else:
            port4_bytes+=packetsize + 40               ## Increasing bytes through this bucket
            port4_bytes_untilnow+=packetsize + 40
          
            new_port_dictionary[destinationport] = 4   ## Adding Port to dictonary  
            
    
def roundrobin(packetsize): ## Function perform load balancing using round robin
    
    ##Accessing global variables
    global p1flag
    global p2flag
    global p3flag
    global p4flag
    global p1_packet_bytes
    global p2_packet_bytes
    global p3_packet_bytes
    global p4_packet_bytes
    global p1_packets
    global p2_packets
    global p3_packets
    global p4_packets
    
    if p1flag:         ##Checking the flag, if true increasing the packet size of this bucket 
        p1_packet_bytes+=packetsize
        p1_packets+=1
        p1flag = False
        p2flag = True
        p3flag = False
        p4flag = False
    elif p2flag:      ##Checking the flag, if true increasing the packet size of this bucket
        p2_packet_bytes+=packetsize
        p2_packets+=1
        p1flag = False
        p2flag = False
        p3flag = True
        p4flag = False
    elif p3flag:     ##Checking the flag, if true increasing the packet size of this bucket
        p3_packet_bytes+=packetsize
        p3_packets+=1
        p1flag = False
        p2flag = False
        p3flag = False
        p4flag = True
    elif p4flag:    ##Checking the flag, if true increasing the packet size of this bucket
        p4_packet_bytes+=packetsize
        p4_packets+=1
        p1flag = True
        p2flag = False
        p3flag = False
        p4flag = False

##Function to calculate the bit rate for each bucket for roundrobin
def roundrobin_bitrate(): 
    p1_bitrate.append((p1_packet_bytes + p1_packets * 40.0) * 8 / (300.00*1024))
    p2_bitrate.append((p2_packet_bytes + p2_packets * 40.0) * 8 / (300.00*1024))
    p3_bitrate.append((p3_packet_bytes + p3_packets * 40.0) * 8 / (300.00*1024))
    p4_bitrate.append((p4_packet_bytes + p4_packets * 40.0) * 8 / (300.00*1024))
    roundrobin_bitrates = []
    roundrobin_bitrates.append((p1_packet_bytes + p1_packets * 40.0) * 8 / (300.00*1024))
    roundrobin_bitrates.append((p2_packet_bytes + p2_packets * 40.0) * 8 / (300.00*1024))
    roundrobin_bitrates.append((p3_packet_bytes + p3_packets * 40.0) * 8 / (300.00*1024))
    roundrobin_bitrates.append((p4_packet_bytes + p1_packets * 40.0) * 8 / (300.00*1024))
    roundrobin_bitrates.sort()   
    maxdiff.append(roundrobin_bitrates[3] - roundrobin_bitrates[0])

##Function to calculate the  bit rate of each bucket for the present window
def port_bitrate():      
    port1_bitrate.append((port1_bytes) * 8/ (300.00*1024))
    port2_bitrate.append((port2_bytes) * 8/ (300.00*1024))
    port3_bitrate.append((port3_bytes) * 8/ (300.00*1024))
    port4_bitrate.append((port4_bytes) * 8/ (300.00*1024))
    port_bitrates = []
    port_bitrates.append((port1_bytes) * 8/ (300.00*1024))
    port_bitrates.append((port2_bytes) * 8/ (300.00*1024))
    port_bitrates.append((port3_bytes) * 8/ (300.00*1024))
    port_bitrates.append((port4_bytes) * 8/ (300.00*1024))
    port_bitrates.sort()
    port_maxdiff.append(port_bitrates[3] - port_bitrates[0])


## Reintialize the variable after the window finshes
def reset_roundrobin():
    ##Accsessing global variable
    global p1_packet_bytes 
    global p2_packet_bytes
    global p3_packet_bytes
    global p4_packet_bytes
    
    global p1_packets
    global p2_packets
    global p3_packets
    global p4_packets
    

    
    p1_packets = 0
    p2_packets = 0
    p3_packets = 0
    p4_packets = 0
    
    p1_packet_bytes = 0
    p2_packet_bytes = 0
    p3_packet_bytes = 0
    p4_packet_bytes = 0

    
## Reintialize the variable after the window finshes
def reset_port_lists():
    ##Accsessing global variable
    global port1_bytes
    global port2_bytes
    global port3_bytes
    global port4_bytes

    global port1_packets
    global port2_packets
    global port3_packets
    global port4_packets

    global port1_list
    global port2_list
    global port3_list
    global port4_list    
            
    port1_bytes = 0
    port2_bytes = 0
    port3_bytes = 0
    port4_bytes = 0

    port1_packets = 0
    port2_packets = 0
    port3_packets = 0
    port4_packets = 0


    
    
for i in range(0, len(splitfile)):                                                            
    splitline = splitfile[i].split()       ## Spliting the line to obtain indivisual elements
    totalfile.append(splitline)            ## Adding the elemnts in total file 
    packettime = float(splitline[0])       ## Converting string to float
    packetsize = int(splitline[5])         ## Converting string to Integer
    percent(packetsize)                    
    ippackets(int(splitline[1]), packetsize)
    portpackets(int(splitline[4]), packetsize)
    if  packettime > windowendtime:        ## Checking if window has finished 
        if windowscounter == 0:            ## Checking whether the window has finished for the first time
            windowsbitrate.append((totalpayload + windowpacketcounter *40) * 8 / (300.00*1024))  ## Calculating bit raye for this window
            windowsbytesuntilnow = totalpayload                       
            windowendtime+=300             ## increasing the window size by three hundred
            windowpacketcounter = 0            
            windowscounter+=1            
        else:
            windowsbitrate.append(((totalpayload - windowsbytesuntilnow) + windowpacketcounter * 40) * 8 / (300.00*1024))
            windowsbytesuntilnow = totalpayload            
            windowendtime+=300
            windowpacketcounter = 0
            windowscounter+=1            

        roundrobin_bitrate()
        reset_roundrobin()
        port_bitrate()
        reset_port_lists()        
        
    addpacket(packetsize, tuple(splitline[1]+splitline[2]+splitline[3]+splitline[4])) ##Creating the tuple of source IP, source port, Destination IP, Destination port  
    roundrobin(packetsize)
    totalpayload = totalpayload + packetsize
    windowpacketcounter+=1                


splitfirstline = totalfile[0][0]
splitlastline = totalfile[len(totalfile)-1][0]
totaltime = float(splitlastline) - float(splitfirstline)

totalBytes = (totalpayload + (totalPackets * 40)) * 8 ## Calculating the total number of bytes


## Printing Results using PrettyTable

print "Total Packets:" + str(totalPackets)
print "Total Bytes:" + str(totalBytes)
print "Total Time:" + str(totaltime)
print "Bit Rate:" + str((totalBytes / totaltime)/1024)                          

windows_timings = ["0 - 299", "300 - 599", "600 - 899", "900 - 1199", "1200 - 1499", "1500 - 1799", "1800 - 2099", "2100 - 2399", "2400 - 2699",
                   "2700 - 2999", "3000 - 3299", "3300 - 3599"]
table = PrettyTable()
table.add_column("Window Timings",windows_timings)
table.add_column("Average Bit Rate (Kb/s)",windowsbitrate)
print table

print '\n'

payload_sizes = ["0", "1 - 127", "128 - 255", "256 - 383", "384 - 511", "512"]
table1 = PrettyTable()
table1.add_column("Payload Size(byte)", payload_sizes)
table1.add_column("Percentage based on number of packets", [x * (100.00/totalPackets) for x in packetpercent])
print table1

print '\n'

iplist = sorted(ipdictionary.iteritems(), key= lambda x: x[1][1], reverse=True)
table2 = PrettyTable()
source_ips = []
traffic_bytes = []
source_ips.append(iplist[0][0])
source_ips.append(iplist[1][0])
source_ips.append(iplist[2][0])
traffic_bytes.append(iplist[0][1][1])
traffic_bytes.append(iplist[1][1][1])
traffic_bytes.append(iplist[2][1][1])
table2.add_column("Source IP" , source_ips)
table2.add_column("Traffic (bytes)" , traffic_bytes)
table2.add_column("Traffic Percentage" , [x * (800.00/totalBytes) for x in traffic_bytes])
print table2



print '\n'

portlist = sorted(portdictionary.iteritems(), key = lambda y: y[1][1], reverse = True)
table3 = PrettyTable()
dest_ports = []
dest_bytes = []
dest_ports.append(portlist[0][0])
dest_ports.append(portlist[1][0])
dest_ports.append(portlist[2][0])
dest_bytes.append(portlist[0][1][1])
dest_bytes.append(portlist[1][1][1])
dest_bytes.append(portlist[2][1][1])
table3.add_column("Destination Port", dest_ports)
table3.add_column("Traffic(bytes)", dest_bytes)
table3.add_column("Traffic Percentage (%)", [x * (800.00/totalBytes) for x in dest_bytes])
print table3



print '\n'


table4 = PrettyTable()
table4.add_column("Window Timings (sec)", windows_timings)
table4.add_column("P1 (kb\s)", p1_bitrate)
table4.add_column("P2 (kb\s)", p2_bitrate)
table4.add_column("P3 (kb\s)", p3_bitrate)
table4.add_column("P4 (kb\s)", p4_bitrate)
table4.add_column("Max Diff", maxdiff)
print table4


print '\n'

table5 = PrettyTable()
table5.add_column("Window Timings (sec)", windows_timings)
table5.add_column("P1 (kb\s)", port1_bitrate)
table5.add_column("P2 (kb\s)", port2_bitrate)
table5.add_column("P3 (kb\s)", port3_bitrate)
table5.add_column("P4 (kb\s)", port4_bitrate)
table5.add_column("Max Diff", port_maxdiff)
print table5


