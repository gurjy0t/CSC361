"""
@Author: Gurjyot Grewal
StudentID: V00820022
Class: CSC361

Basic function: Given a pcap/pcapng file of a traceroute execution. This program
                will print out, according to the specification:
                The originating source, 
                    final destination,
                    intermediate routers,
                    datagram fragmentation (if any),
                    Avg RTT times for intermediate routers; and
                    S.D RTT times for intermediate routers

Usage information, needed libraries and other details can be found in the README.txt file
"""

import sys
import pcapy
from pcapy import open_offline
from impacket import ICMP6
from impacket import ImpactDecoder, ImpactPacket
import numpy


class u_pckt():
    def __init__(self, frame, udp_header, ip_header, ts):
        self.frame = frame
        self.udp_header = udp_header
        self.ip_header = ip_header
        self.ts = ts

    def __str__(self):
        src = " src port: " + str(self.udp_header.get_uh_sport())
        dst = " dst port: " + str(self.udp_header.get_uh_dport())
        src_ip = " src ip: " + str(self.ip_header.get_ip_src())
        dst_ip = " dst ip: " + str(self.ip_header.get_ip_dst())
        return src+dst+src_ip+dst_ip
    def get_ts(self):
        rv = '{0:.4f}'.format(float(self.ts[0] + (self.ts[1]/1000000.0)))

        return float(rv)

class ic_pckt():
    def __init__(self, frame, icmp_header, ip_header, ts):
        self.frame = frame
        self. icmp_header = icmp_header
        self. ip_header = ip_header
        self.ts = ts
    def get_ts(self):
        rv = '{0:.4f}'.format(float(self.ts[0] + (self.ts[1]/1000000.0)))
        return float(rv)

def is_ip(ether):
    return (ether.get_ether_type() == ImpactPacket.IP.ethertype)

def icmp_or_udp(iphdr):
    ret_val = True if (iphdr.get_ip_p()==17 or iphdr.get_ip_p()==1) else False
    return ret_val

def get_version(pcap_file):
    '''
    This program run through the pcap file, and at the first datagram probe form the origin, decides whether
    it is generated using windows or linux.

    ICMP ECHO -> Windows
    UDP -> Linux
    '''


    try:
        cap = open_offline(pcap_file)
    except:
        print("The file is not of the correct type")
    header, payload = cap.next()

    while header:
        decoder = ImpactDecoder.EthDecoder()
        ether = decoder.decode(payload)
        
        if not is_ip(ether):
            header, payload = cap.next()
            continue
        iphdr = ether.child()
        
        if not icmp_or_udp(iphdr):
            header, payload = cap.next()
            continue
        
        first_packet_protocol = iphdr.get_ip_p()

        if first_packet_protocol == 1:
            icmp_pkt = iphdr.child()
            if(icmp_pkt.get_icmp_type() == 8):
                return "Windows"    
        if first_packet_protocol == 17:
            return "Linux"

def get_linux_packets(pcap_file):
    '''
    This program pairs UDP probes and ICMP error packets.
    Furthermore it records all unique protocols seen.
    It also collects fragmets of ip datagrams, if there are any.

    '''
    print("get_linux_packets")
    cap = open_offline(pcap_file)
    header, payload = cap.next()
    udp = 17
    icmp = 1
    icmp_echo = 8
    icmp_error = 11
    dns = 53
    stp = 123
    icmp_pairs = {}
    packets = []
    protocls = []
    i=0
    j = 0
    k=0
    num_icmp= 0
    banana=0
    icmp_keys=[]
    udp_keys=[]
    pairs = []
    original_src = 0
    original_dst = 0
    fragments = {}
    while header:
        decoder = ImpactDecoder.EthDecoder()
        ether = decoder.decode(payload)
        
        if not is_ip(ether):
            header, payload = cap.next()
            continue
        
        iphdr = ether.child()
        proto = iphdr.get_ip_p()
        if proto not in protocls:
            protocls.append(proto)
        if proto != icmp and proto != udp:
            header, payload = cap.next()
            continue

        if proto == udp:
            udp_pkt = iphdr.child()
            src_p = udp_pkt.get_uh_sport()
            dst_p = udp_pkt.get_uh_dport()

            if (src_p == dns or dst_p == dns) or (src_p == stp or dst_p == stp):                    
                header, payload = cap.next()
                continue

            if iphdr.get_ip_ttl()==1:
                original_src = iphdr.get_ip_src()
                original_dst = iphdr.get_ip_dst()

            key = str(src_p)+str(dst_p)
            udp_keys.append(key)

            if key not in icmp_pairs:
                icmp_pairs[key] = u_pckt(header, udp_pkt, iphdr, header.getts())
        
            j+=1
        
        if proto == icmp:
            num_icmp+=1
            icmp_pckt = iphdr.child()
            if icmp_pckt.get_icmp_type()==icmp_error or 3:# and banana == 0:
                banana+=1
                ether_off = ether.get_header_size()
                ip_off = iphdr.get_header_size()
                ic_off = icmp_pckt.get_header_size()    
                total_off = ether_off + ip_off + ic_off    
                
                uh_decoder = ImpactDecoder.UDPDecoder()
                original_udp = uh_decoder.decode(payload[total_off+20:])
                key = str(original_udp.get_uh_sport()) +  str(original_udp.get_uh_dport())
                icmp_keys.append(key)
                
                if key in icmp_pairs:            
                    pair1 = icmp_pairs.pop(key)
                    pairs.append((pair1, ic_pckt(header, icmp_pckt, iphdr, header.getts()))) 

        fragment_offset = iphdr.get_ip_off() << 3
        if iphdr.get_ip_src() == original_src and iphdr.get_ip_dst() == original_dst:
            if not iphdr.get_ip_df() and (iphdr.get_ip_mf() == 1 or fragment_offset > 0):
                if iphdr.get_ip_id() not in fragments:
                    fragments[iphdr.get_ip_id()] = [] #1
                    fragments[iphdr.get_ip_id()].append(iphdr)
                else:
                    fragments[iphdr.get_ip_id()].append(iphdr) #+= 1
            else:
                if iphdr.get_ip_id() in fragments:
                    fragments[iphdr.get_ip_id()].append(iphdr) #+= 1

        header, payload = cap.next()    
    
    probe_packets = []
    keys_in_pp = []

    for pair in pairs:
        if (pair[0].ip_header.get_ip_src() == original_src or pair[0].ip_header.get_ip_dst() == original_dst):
            probe_packets.append(pair[0])
            keys_in_pp.append(pair[0].ip_header.get_ip_id())

    for key in icmp_pairs:
        if (icmp_pairs[key].ip_header.get_ip_src() == original_src or icmp_pairs[key].ip_header.get_ip_dst()==original_dst) and \
            icmp_pairs[key].ip_header.get_ip_id() not in keys_in_pp:
            probe_packets.append(icmp_pairs[key])
            
    
    probe_packets.sort(key = lambda x:x.get_ts())
    pairs.sort(key = lambda x: x[0].ip_header.get_ip_ttl())
    
    return pairs, protocls, fragments, probe_packets

def get_win_packets(pcap_file):

    '''
    Similarly to get_linux_packets
    This program pairs probes and ICMP error packets, however the probes are ICMP Echo and not UDP/
    Furthermore it records all unique protocols seen.
    It also collects fragmets of ip datagrams, if there are any.

    '''

    cap = open_offline(pcap_file)
    header, payload = cap.next()

    icmp_pairs = {}
    packets = []
    protocls=[]
    i=0
    fragments = {}
    while header:
        decoder = ImpactDecoder.EthDecoder()
        ether = decoder.decode(payload)
        
        if not is_ip(ether):
            header, payload = cap.next()
            continue
        
        iphdr = ether.child()
        proto = iphdr.get_ip_p()
        
        if proto not in protocls:
            protocls.append(proto)
        
        if proto != 1:
            header, payload = cap.next()
            continue
        
        if iphdr.get_ip_ttl() == 1:
            original_src = iphdr.get_ip_src()
            original_dst = iphdr.get_ip_dst()
        
        icmp_pckt = iphdr.child()
        ether_off = ether.get_header_size()
        ip_off = iphdr.get_header_size()
        ic_off = icmp_pckt.get_header_size()    
        total_off = ether_off + ip_off + ic_off    
        seq = icmp_pckt.get_icmp_seq()

        if icmp_pckt.get_icmp_type() == 11:
            ic_decoder = ImpactDecoder.ICMPDecoder()
            original_icmp = ic_decoder.decode(payload[total_off+20:])
            seq = original_icmp.get_icmp_seq()
            
        if seq not in icmp_pairs:
            icmp_pairs[seq] = ic_pckt(header, ic_pckt, iphdr, header.getts())

        else:
            temp = icmp_pairs.pop(seq)
            packets.append((temp, ic_pckt(header, icmp_pckt, iphdr, header.getts()) ))

        fragment_offset = iphdr.get_ip_off() << 3
        if iphdr.get_ip_src() == original_src and iphdr.get_ip_dst() == original_dst:
            
            if not iphdr.get_ip_df() and (iphdr.get_ip_mf() == 1 or fragment_offset > 0):
                if iphdr.get_ip_id() not in fragments:
                    fragments[iphdr.get_ip_id()] = [] 
                    fragments[iphdr.get_ip_id()].append(iphdr)
                else:
                    fragments[iphdr.get_ip_id()].append(iphdr) 
            else:
                if iphdr.get_ip_id() in fragments:
                    # s = 's'
                # else:
                    fragments[iphdr.get_ip_id()].append(iphdr)
        header, payload = cap.next()    

    packets.sort(key = lambda x: x[0].ip_header.get_ip_ttl())
    probe_packets = []
    # print icmp_pairs
    for pair in packets:
        probe_packets.append(pair[0])
    for key in icmp_pairs:
        if icmp_pairs[key].ip_header.get_ip_src() == original_src:
            probe_packets.append(icmp_pairs[key])
    return packets, protocls, fragments, probe_packets

def analyze_pairs(pairs):
    '''
    This function analyzes the request/error pairs 
    and returns the intermediate router ips by hop and rtt lists
    '''
    original_src = pairs[0][0].ip_header.get_ip_src()
    original_dst = pairs[0][0].ip_header.get_ip_dst()
    routers = []
    for pair in pairs:
        src_ip = pair[1].ip_header.get_ip_src()
        if (src_ip not in routers) and src_ip != original_src and src_ip != original_dst:
            routers.append(pair[1].ip_header.get_ip_src())
    temp = {}
    for router in routers:
        temp[router] = [] 
    temp[original_dst] = []

    for pair in pairs:
        probe_pckt = pair[0]
        response_pckt = pair[1]
        router_ip = response_pckt.ip_header.get_ip_src()
        rtt = response_pckt.get_ts() - probe_pckt.get_ts()
        temp[router_ip].append(rtt)
    return routers, temp

def analyze_frags(probe_packets, fragments):
    '''
    This function returns a list of all fragmented original datagrams,
    if any
    '''
    rv = []
    for p in probe_packets:  
        if(p.ip_header.get_ip_id() in fragments):
            frag_size = len(fragments[p.ip_header.get_ip_id()])
            if frag_size > 1:
                rv.append((probe_packets.index(p)+1, frag_size, fragments[p.ip_header.get_ip_id()][-1].get_ip_off()<<3))
    return rv

def logger(intermediate_routers, rtts, protos_seen, frag_analysis, probe_packets):
    '''
    This function handles all the printing
    '''
    protocols = {17:"UDP",
                 6:"TCP",
                 1:"ICMP", 
                 2:"IGMP",
                 5:"ST",
                 47:"PPTP",
                 27:"RDP",
                 3:"GGP"}

    original_src = probe_packets[0].ip_header.get_ip_src()
    original_dst = probe_packets[0].ip_header.get_ip_dst()
    
   
    print "The IP address of the source node: " + str(original_src) 
    print "The IP address of ultimate destination node: " + str(original_dst) + '\n'
    print "The IP addresses of the intermediate destination nodes: "
    for router in intermediate_routers:
        print "\t router " + str(intermediate_routers.index(router)+1) + ": " + router
    print
    print "The values in the protocol field of IP headers: "
    for proto in protos_seen:
        if proto not in protocols:  continue
        print str(proto) + ": " + protocols[proto]
    print
    for item in frag_analysis:
        print "The number of fragments created from the original datagram D" + str(item[0]) + " is: " + str(item[1])
        print "The offset of the last fragment is: " + str(item[2])
        print 

    for router in intermediate_routers:
        list_of_rtts = rtts[router]
        rtt =  "The avg RRT between "+ original_src + " and " + router + " is " + str( round((sum(list_of_rtts)/float(len(list_of_rtts)))*1000, 2)  ) + " ms"#str(sum(list_of_rtts)/float(len(list_of_rtts)))
        sd = " the s.d is 0ms" if len(list_of_rtts)<2 else " the s.d is " + str( round(numpy.std(list_of_rtts)*1000, 2) ) + " ms"
        print rtt + sd
        
    if original_dst in rtts:
        list_of_rtts = rtts[original_dst]        
        rtt = "The avg RRT between "+ original_src + " and " + original_dst + " is " + str( round((sum(list_of_rtts)/float(len(list_of_rtts)))*1000, 2)  )
        sd = " the s.d is 0ms" if len(list_of_rtts)<2 else " the s.d is " + str( round(numpy.std(list_of_rtts)*1000, 2) ) + " ms"
        print rtt + sd

    #used for Requirement 2.
    # per_ttl = {}
    # for packet in probe_packets:
    #     if packet.ip_header.get_ip_ttl() in per_ttl:
    #         per_ttl[packet.ip_header.get_ip_ttl()]+=1
    #     else:
    #         per_ttl[packet.ip_header.get_ip_ttl()] = 1
    #     # print packet.ip_header.get_ip_ttl()    

    # print per_ttl
def main(argv):
    print "Analyzing the file " + str(argv[1]) +  ". . ."
    version = get_version(argv[1])
    print "file was generated on " + version
    print
    
    pairs, protos_seen, fragments, probe_packets = get_win_packets(argv[1]) if version=="Windows" else get_linux_packets(argv[1])

    intermediate_routers, rtts = analyze_pairs(pairs)
    frag_analysis = analyze_frags(probe_packets, fragments)
    logger(intermediate_routers, rtts, protos_seen, frag_analysis, probe_packets)
    
if __name__ == '__main__':
    main(sys.argv)