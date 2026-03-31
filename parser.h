#ifndef PARSER_H
#define PARSER_H

#include "headers.h"

#include <pcap.h>
#include <string>

using namespace std;


//--------------------- STAGE 3 ---------------------
// Extracting meaningful info from raw bytes
string get_ether_type(u_short eth_type);

string get_app_name(u_short eth_type);



//----------------------------- STAGE 4 -------------------------------
void detect_port_scan(IPv4Header*, TcpUdpHeader*);



//----------------------------- STAGE 5 -------------------------------
string parse_sni(
    const u_char* payload, 
    int payload_len,
    IPv4Header* ip_header, 
    TcpUdpHeader* tcp_udp_header
);
// It checks if the packet is a TLS ClientHello and if so, 
// it parses the SNI from the TLS extensions.

// 1. IP protocol == TCP    → ip_header->protocol == 6
// 2. Dest port == 443      → ntohs(tcp->dest_port) == 443
// 3. payload[0] == 0x16   → TLS record
// 4. payload[5] == 0x01   → Client Hello

#endif