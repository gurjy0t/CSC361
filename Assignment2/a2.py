"""
@Author: Gurjyot Grewal
StudentID: V00820022
Class: CSC361

Basic function: Given a pcap file, the program will output the 4 sections; A, B, C and D.
                Section A will signify the total number of connections in the file.
                Section B will list connection details for each of the connections and will 
                    provide additional details for 'complete' connections (SxF1 or greater)
                Section C will provide general statistics for ALL connections
                Section D will list detailed statistics for COMPLETE connections

Usage information, needed libraries and other details can be found in the README.txt file
"""

import sys
import pcapy
from pcapy import open_offline
from impacket import ImpactDecoder, ImpactPacket

class connection():
    '''
    This class represents the connection object, used to uniquely identify connections.
    Each connection object has many attributes, which will be used in statistics.

    To initialize a connection object, the 4 fields:
        source_ip, source_port, dest_ip and dest_port
    are mandatory.
    '''
    def __init__(self,source_ip, source_port, dest_ip, dest_port):
        self.source_ip = source_ip
        self.source_port = source_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.packets=[]
        self.has_rst = False
        self.outgoing_packets = 0
        self.incoming_packets = 0
        self.total_packets = self.incoming_packets + self.outgoing_packets
        self.state = "s0f0"
        self.bytes_sent=0
        self.bytes_recieved=0
        self.total_bytes = 0
        self.start_time=0
        self.end_time=0
        self.duration=0
        self.complete=False
        self.rtts=[]
        self.wins=[]

    #setters
    def set_outgoing(self, outgoing):
        self.outgoing_packets = outgoing
        self.total_packets = self.incoming_packets + self.outgoing_packets
    def set_complete(self):
        self.complete = True
    def is_complete(self):
        return self.complete
    def set_incoming(self, incoming):
        self.incoming_packets = incoming
        self.total_packets = self.incoming_packets + self.outgoing_packets
    def set_rst(self):
        self.has_rst = True
    def set_end_time(self, time):
        self.end_time = time
    def set_duration(self, time):
        self.duration = time
    def set_start_time(self, time):
        self.start_time = time
    def set_state(self, new_state):
        self.state = new_state
    def set_rtts(self, rtt_list):
        self.rtts = rtt_list
    def set_wins(self, win_list):
        self.wins=win_list
    def set_bytes_sent(self, num_bytes):
        self.bytes_sent=num_bytes
    def set_bytes_recieved(self, num_bytes):
        self.bytes_recieved=num_bytes
    def set_total_bytes(self):
        self.total_bytes = self.bytes_sent + self.bytes_recieved

    def addPacket(self, packet):
        self.packets.append(packet)

    #getter
    def get_start_time(self):
        return self.start_time

class pckt():
    '''
    This is a packet class. Each packet contains a:
    Frame,
    TCP Header,
    IP Header; AND
    Timestamp
    '''
    def __init__(self, frame, th, ih, ts):
        self.frame = frame
        self.th = th
        self.ih = ih
        self.ts=ts

    def to_dec(self):
        getcontext().prec=15
        x = Decimal(str(self.ts[0]) + "." + str(self.ts[1]))
        return x

class tcp_state_machine():
    '''
    This class is used to maintain the state of a connection
    '''
    def update_state(self):
        self.state='s'+str(self.num_s) + 'f' + str(self.num_f)
    def __init__(self):
        self.num_s=0
        self.num_f=0
        self.update_state()
    def transition(self, flag):
        if flag == 'SYN':   self.num_s+=1
        if flag == 'FIN':   self.num_f+=1
        self.update_state()
    def reset(self):
        self.__init__()

def sort_connections(websites):
    '''
    This function sorts the packets into their unique connection objects.
    Each connection is uniquely identified by the TCP 4-tuple

    Input: A dictionary of lists containing packets, keys being unique website ips
    Output: A connection tuple list and an object with connection objects, each representing
            a unique connection.
    '''
    s = 'SYN'
    f = 'FIN'
    connection_tuples=[]
    connections = {}

    for key in websites:
        packets = websites[key]
        for packet in packets:
            tcp_header = packet.th
            ip_header = packet.ih
            sport = tcp_header.get_th_sport()
            dport = tcp_header.get_th_dport()
            sip = ip_header.get_ip_src()
            dip = ip_header.get_ip_dst()
            
            con ={sport, sip, dport, dip}
            if con not in connection_tuples:
                connection_tuples.append(con)
                cnxn = connection(sip, sport, dip, dport)
                connections[connection_tuples.index(con)] = cnxn
            x=connection_tuples.index(con)


            connections[x].addPacket(packet)
    return connection_tuples, connections
                
def analyze_connection(connection, start_time):
    '''
    This function takes a connection object and iterates through
    its packets and identifies key connection statistics such as:
    start_time, end_time, duration, packets sent/recieved, bytes sent/recieved.
    It also creates a list of rtts for seq/ack pairs and a list of window sizes.

    Input: A connection object and the start_time for capture for relative time
    Output: This function sets the following attributes of the connection object:
            State of connection,
            Packets sent/recieved/total,
            Data sent/recieved/total,
            List of RTTS,
            List of Recieve Window sizes,
            Start Time,
            End Time (if ended), &
            Duration
    '''
    s="SYN"
    f="FIN"
    sp = connection.packets[0].th.get_th_sport()
    dp = connection.packets[0].th.get_th_dport()
    outgoing=0
    incoming=0
    starting_seq = connection.packets[0].th.get_th_seq()
    fsm = tcp_state_machine()
    data_sent=0
    data_recieved=0
    last_incoming=0
    starting=0
    ending=0
    duration=0
    i=1
    first_syn=False
    seq_ack={}
    rtts=[]
    wins=[]
    for pck in connection.packets:
        wins.append(pck.th.get_th_win())
        ip_header = pck.ih.get_ip_hl() * 4
            
        total_len = pck.ih.get_ip_len()
        tcp_header = pck.th.get_th_off() * 4

        if pck.th.get_SYN():
            if first_syn==False:  
                starting = float(pck.ts[0] + (pck.ts[1]/1000000.0)) - (start_time[0] + (start_time[1]/1000000.0))
                first_syn=True
            fsm.transition(s)
        
        if pck.th.get_FIN():    
            ending = float(pck.ts[0] + (pck.ts[1]/1000000.0)) - (start_time[0] + (start_time[1]/1000000.0))
            if connection.is_complete()==False and int(fsm.state[1])>0:   
                connection.set_complete()
            fsm.transition(f)
        
        if pck.th.get_RST():    
            connection.set_rst()
        data_size=(total_len - ip_header - tcp_header)
        if pck.th.get_th_sport()==sp:   
            outgoing+=1
            data_sent+= data_size
        if pck.th.get_th_sport()==dp:
            data_recieved+= data_size
            last_incoming=pck
            incoming+=1
        seq_ack[pck.th.get_th_seq() + data_size] = float(pck.ts[0] + (pck.ts[1]/1000000.0))
        if pck.th.get_th_ack() in seq_ack:
            rtts.append(float(pck.ts[0] + (pck.ts[1]/1000000.0)) - seq_ack[pck.th.get_th_ack()])
    duration = ending - starting
    connection.set_wins(wins)
    connection.set_rtts(rtts)
    connection.set_start_time(starting)
    connection.set_end_time(ending)
    connection.set_duration(duration)
    connection.set_bytes_sent(data_sent)
    connection.set_bytes_recieved(data_recieved)
    connection.set_total_bytes()
    connection.set_outgoing(outgoing)
    connection.set_incoming(incoming)
    connection.set_state(fsm.state)
    
def analyzer(argv):
    '''
    This function goes through the pcap file and sorts the packets
    by unique IP address effectively obtaining a list of unique websites
    and the packets passed to/from them.

    Input: pcap file
    Output: This function calls the outputer which generates final output
    '''
    unique_websites={}
    try:
        cap = open_offline(argv[1])
        header,payload = cap.next()
        # print(ImpactPacket.IP.ethertype)
        client_ip=''
        if ImpactDecoder.EthDecoder().decode(payload).get_ether_type() == ImpactPacket.IP.ethertype:
            client_ip=ImpactDecoder.EthDecoder().decode(payload).child().get_ip_src()
        start_time = header.getts()
        i=1
        j=0
        while header:
            # print j
            # j+=1
            # Parse the Ethernet packet
            decoder = ImpactDecoder.EthDecoder()
            ether = decoder.decode(payload)
            if ether.get_ether_type() != ImpactPacket.IP.ethertype:
                header, payload = cap.next()
                continue
            
			# Parse the IP packet inside the Ethernet packet
            iphdr = ether.child()
            if iphdr.get_ip_p()!=6:
                header, payload = cap.next()
                continue
            source_ip = iphdr.get_ip_src()
            dest_ip = iphdr.get_ip_dst()
            if i==1:    
                client_ip=source_ip
                i+=1
			# Parse the TCP packet inside the IP packet
            tcphdr = iphdr.child()
            source_port = tcphdr.get_th_sport()
            dest_port = tcphdr.get_th_dport()
            ts = header.getts()
            pck = pckt(header, tcphdr, iphdr, ts)
            key = source_ip if source_ip!=client_ip else dest_ip
            if (key not in unique_websites):
                unique_websites[key] = [] 
            unique_websites[key].append(pck)
            header, payload = cap.next()

    except pcapy.PcapError:
        print('exception')


    connection_tuples, connections = sort_connections(unique_websites) 
    connections_list = []
    for c in connections:
        analyze_connection(connections[c],start_time)
        connections_list.append(connections[c])
        
    connections_list.sort(key = lambda x: x.get_start_time())   
    outputter(connections_list)

def outputter(connections_list):
    '''
    This is the function where the output of the program is generated.
    At this point, the 'analysis' of each connection is done, and the details
    are stored inside the connection objects. Statistics on 'all' connections
    is done here by mergings lists of each connection object. Lists such
    as RTTs, WindowSizes and Durations.

    Input: A sorted list of connection objects, each one passed through the analyzer.
           List is sorted by connection.start_time
    '''
    total_connections=len(connections_list)
    complete_connections=0
    reset_connections=0
    rtts=[]
    wins=[]
    all_packets=[]
    all_durations=[]
    for con in connections_list:
        if con.has_rst:    reset_connections+=1
        if con.is_complete():
            complete_connections+=1
            rtts+=con.rtts
            wins+=con.wins
            all_packets.append(con.total_packets)
            all_durations.append(con.duration)
    
    connections_still_open_at_end = total_connections-complete_connections
    
    nl="\n"
    dashes = "--------------------------------------------------------------------"
    print("A) Total Number of Connections: " + str(len(connections_list)))
    print(dashes)
    
    print("B) Connection Details: " + nl)
    
    for i in range(len(connections_list)):
        w=""
        if connections_list[i].has_rst:    w=" +R "
        s = "Connection " + str(i+1) +":"+ nl + \
        " Source Address: " + connections_list[i].source_ip + nl+\
        " Destination address: " + connections_list[i].dest_ip + nl+\
        " Source Port: " + str(connections_list[i].source_port) + nl+\
        " Destination Port:" + str(connections_list[i].dest_port) + nl+\
        " Status: " + connections_list[i].state + w + nl
        # (Only if the connection is complete provide the following information)
        if (connections_list[i].is_complete()):
            s+= " Start time: " + str(connections_list[i].start_time) + nl+\
            " End Time: " + str(connections_list[i].end_time) + nl+\
            " Duration: " + str(connections_list[i].duration) + nl+\
            " Number of packets sent from Source to Destination: " + str(connections_list[i].outgoing_packets) + nl+\
            " Number of packets sent from Destination to Source: " + str(connections_list[i].incoming_packets) + nl+\
            " Total number of packets: " + str(connections_list[i].total_packets) + nl+\
            " Number of data bytes sent from Source to Destination: " + str(connections_list[i].bytes_sent) + nl+\
            " Number of data bytes sent from Destination to Source: " + str(connections_list[i].bytes_recieved) + nl+\
            " Total number of data bytes: " + str(connections_list[i].total_bytes) + nl
        s+=" END"
        print(s)
        print(dashes)

    print("C) General: " + nl)
    print("Total number of complete TCP connections: " + str(complete_connections))
    print("Number of reset TCP connections: " + str(reset_connections))
    print("Number of TCP connections that were still open when the trace capture ended: " + str(connections_still_open_at_end) + nl)
    print(dashes + nl)

    print("D) Complete TCP Connections: " + nl)

    print("Minimum time duration: " + printable(min(all_durations)) + "s")
    print("Mean time duration: " + printable(mean(all_durations))+ "s")
    print("Maximum time duration: " + printable(max(all_durations))+ "s")
    print(nl)
    print("Minimum RTT value: " + printable(min(rtts), True)+ "s")
    print("Mean RTT value: " + printable(mean(rtts), True)+ "s")
    print("Maximum RTT value: " + printable(max(rtts), True)+ "s")
    print(nl)
    print("Minimum number of packets including both send/received: " + str(min(all_packets)))
    print("Mean number of packets including both send/received: " + printable(mean(all_packets)))
    print("Maximum number of packets including both send/received: " + str(max(all_packets)))
    print(nl)
    print("Minimum receive window size including both send/received: " + printable(min(wins)))
    print("Mean receive window size including both send/received: " + printable(mean(wins)))
    print("Maximum receive window size including both send/received: " + printable(max(wins)))

def printable(num, printable=False):
    prec="%.8f" if printable else "%.5f"
    return str(prec % num)
def mean(li):
    return(sum(li)/float(len(li)))    
def main(argv):
    analyzer(argv)
   
if __name__ == '__main__':
    main(sys.argv)