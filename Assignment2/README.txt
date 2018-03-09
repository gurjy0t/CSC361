README:

This is the readme for a2.py, an application built for CSC361 Assignment 2. The purpose of this application is to, given a pcap file, generate a four-section output as stated in the assignment description. The four sections are:

Section A - The total number of connections in the file
Section B - Information about each connection 
Section C - Statistics of all Connections
Section D - Additional statistics of complete connections*

* A complete connection for this assignment is considered any connection with atleast 1 FIN (with 1 or more SYNS)

This application runs on Python2 version 2.7.10 and will not run on Python3

REQUIRED LIBRARIES: pcapy and ImPacket (Impacket does not support python3)

USAGE:
	python a2.py /path/to/pcap/file

	To use the a2.py application, run the above command. If the file you are testing 	with is in the same directory, you do not need to list its path.

Example	python a2.py sample-capture-file

MORE:

I will also outline what the high-level goal of the application is and how its done.

Step 1)

The packets are sorted by unique IP address. Since the assignment description explicitly states that there will only be one client and many servers, each server is identified by its ip. Packets are then sorted by these ips (This is done within the analyzer function). NOTE: There may be many connections to the same server.

Step 2) 

For each list of packets for a unique website, a list of connections is made. According to the announcements, a 4-tuple uniquely identifies a connection (meaning I do not need to worry about duplicate connections between the same server and client using the same ports). A collection of connection objects is created in the sort_connections function

Step 3)

Each of these connections is then analyzed. From the analysis the following primitive attributes are added to the connections object: State, outgoing_packets, incoming_packets, total_packets, bytes_sent, bytes_received, total_bytes, start_time, end_time (if exists), duration (if exists), complete and has_rst. List attributes assigned: packets, rtts, wins.  

Step 4) 

The outputter function prints the output to console.

The output A is printed as the length of the connections object list

The output to B is printed by iterating through the connections object list and printing connection details depending on if connection.complete==True. During iteration, num_complete and num_reset counters are updated as well as total_packets and durations added to a list to be used later.(num_reset is upped by one if a connection object has an attribute has_rst==True)

The output to C is printed as the counters from step 2. Connections still opened is determined from total connections - complete connections

The output to D is printed by merging each of the connections list attributes: rtts and wins, and then getting the min/max/mean values. The max/min/mean values of the lists keeping total_packets and durations for each connection are also printed.