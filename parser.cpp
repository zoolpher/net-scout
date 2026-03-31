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
    
    if (port_scan_tracker[src_ip].size() > 30) {
        // print warning
        cout << "🚨 PORT SCAN DETECTED\n";
        cout << "Suspicious IP : " << src_ip << "\n";
        cout << "Ports probed  : " << port_scan_tracker[src_ip].size() << "\n";
        
        for (int port : port_scan_tracker[src_ip]) {
            cout << port << " → " << get_app_name(port) << "\n";
        }
        
        // Sleep(5000);  // 5000 milliseconds = 5 seconds
        port_scan_tracker.erase(src_ip);
    }
}


//----------------------------- STAGE 4 -------------------------------
string parse_sni(
    const u_char* payload, 
    int payload_len, 
    IPv4Header* ip_header, 
    TcpUdpHeader* tcp_udp_header) {
    // Implement logic to parse the TLS ClientHello message and extract the SNI
    // This involves parsing the TLS record layer, handshake layer, and extensions
    // Look for the SNI extension (type 0x00) and extract the server name
    
    // 1. IP protocol == TCP    → ip_header->protocol == 6
    // 2. Dest port == 443      → ntohs(tcp->dest_port) == 443
    // 3. payload[0] == 0x16   → TLS record
    // 4. payload[5] == 0x01   → Client Hello

    if (ip_header->protocol == 6 && 
       ntohs(tcp_udp_header->dest_port) == 443 && 
       payload_len > 5 &&
       payload[0] == 0x16 && 
       payload[5] == 0x01) {
        
        // Basic parsing logic to find SNI in the TLS ClientHello
        int pos = 43; // Start of extensions (after fixed ClientHello fields)

        // skip session ID
        u_char session_id_len = payload[pos];
        pos += 1 + session_id_len;

        // skip cipher suites
        u_short cipher_len = (payload[pos] << 8) | payload[pos+1];
        pos += 2 + cipher_len;

        // skip compression methods
        u_char compression_len = payload[pos];
        pos += 1 + compression_len;

        // skip extensions length field
        pos += 2;


        while (pos < payload_len) {
            if (pos + 4 > payload_len) break; // Not enough data for extension header
            
            u_short ext_type = (payload[pos] << 8) | payload[pos + 1];
            u_short ext_len = (payload[pos + 2] << 8) | payload[pos + 3];
            
            if (ext_type == 0x00) { // SNI extension
                int sni_pos = pos + 4;
                if (sni_pos + ext_len > payload_len) break; // Not enough data for SNI
                
                // Parse SNI list
                int sni_list_len = (payload[sni_pos] << 8) | payload[sni_pos + 1];
                int sni_name_pos = sni_pos + 2;
                
                while (sni_name_pos < sni_pos + 2 + sni_list_len) {
                    u_char name_type = payload[sni_name_pos];
                    u_short name_len = (payload[sni_name_pos + 1] << 8) | payload[sni_name_pos + 2];
                    
                    if (name_type == 0x00) { // Hostname
                        string sni((char*)(payload + sni_name_pos + 3), name_len);
                        return sni;
                    }
                    
                    sni_name_pos += 3 + name_len; // Move to next SNI entry
                }
            }
            
            pos += 4 + ext_len; // Move to next extension
        }
    }
    return "";
    
}