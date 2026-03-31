#include <pcap.h>
#include <iostream>

#include "parser.h"
#include <unordered_map>
#include <set>

#include <string>
using namespace std;


//--------------------- STAGE 3 ---------------------
// Extracting meaningful info from raw bytes
string get_ether_type(u_short eth_type) {
    // cout<<eth_type<<"\n";
    switch (eth_type) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x86DD: return "IPv6";
        default: return "Unknown";
    }
    return "Unknown";
}

// pcap_compile()   → compiles the filter string
// pcap_setfilter() → applies it to your handle


//--------------------- STAGE 3 ---------------------
// Gives the app name based on the port number (for TCP/UDP)
string get_app_name(u_short eth_type) {
    switch (eth_type) {
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 53: return "DNS";
        case 25: return "SMTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        default: return "Unknown";
    }
    return "Unknown";
}


//----------------------------- STAGE 4 -------------------------------

unordered_map<string, set<int>> port_scan_tracker;
//   (src_ip) : {set of unique ports visited by that IP}

void detect_port_scan(IPv4Header* ip_header, TcpUdpHeader* tcp_udp_header) {
    // Implement logic to track connection attempts and identify port scans
    // For example, maintain a map of source IPs to attempted ports and counts
    // If a single IP attempts connections to many different ports in a short time, flag it as suspicious

    string src_ip = inet_ntoa(*(struct in_addr*)&ip_header->src_ip);
    port_scan_tracker[src_ip].insert(ntohs(tcp_udp_header->dest_port));

    if (port_scan_tracker[src_ip].size() > 10) {
        // print warning
        cout << "🚨 PORT SCAN DETECTED\n";
        cout << "Suspicious IP : " << src_ip << "\n";
        cout << "Ports probed  : " << port_scan_tracker[src_ip].size() << "\n";

        for (int port : port_scan_tracker[src_ip]) {
            cout << port << " → " << get_app_name(port) << "\n";
        }

        Sleep(5000);  // 5000 milliseconds = 5 seconds
    }
}