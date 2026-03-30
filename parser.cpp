#include <pcap.h>
#include <iostream>

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
