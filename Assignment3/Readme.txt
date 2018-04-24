README:

This is the readme for assignment3.py, an application built for CSC361 Assignment 3. The purpose of this application is to, given a pcap file captured during a trace route execution, to output the following:

Which version the trace route was generated from (WIN/Linux)
The original source IP
The original destination IP
IPs of all intermediate routers
Fragments from original datagram (if any) and offset of last frag
Avg RTTs between all intermediate routers (and destination if any communication)
Standard deviation in RTTs between all intermediate routers


This application runs on Python2 version 2.7.10 and will not run on Python3

REQUIRED LIBRARIES: pcapy, ImPacket (Impacket does not support python3) and numpy

USAGE:

'python assignment3.py /path/to/pcap/file'

To use the assignment3.py application, run the above command. If the file you are testing with is in the same directory, you do not need to list its path.

Example	python assignment3.py trace1.pcapng


