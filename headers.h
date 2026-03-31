#ifndef HEADER_H
#define HEADER_H


#include <pcap.h>


//----------------------------------- stage 3 ---------------------------------------
struct EthernetHeader {
    u_char dest_mac[6];     // initial 6 bytes are destination MAC address
    u_char src_mac[6];      // next 6 bytes are source MAC address
    u_short ether_type;     // next 2 bytes are EtherType (e.g., 0x0800 for IPv4)
};

//----------------------------------- stage 3 ---------------------------------------
struct IPv4Header {
    u_char  version_ihl;    // version + header length
    u_char  tos;            // type of service
    u_short total_length;   // total length
    u_short id;              // identification
    u_short flags_offset;   // flags + fragment offset
    u_char  ttl;            // time to live
    u_char  protocol;       // TCP=6, UDP=17, ICMP=1
    u_short checksum;       // header checksum
    u_int   src_ip;         // source IP
    u_int   dest_ip;        // destination IP
};

//----------------------------------- stage 3 ---------------------------------------
struct TcpUdpHeader {
    u_short src_port;       // source port
    u_short dest_port;      // destination port
    u_int   seq_num;        // sequence number (TCP only)
    u_int   ack_num;        // acknowledgment number (TCP only)
    u_char  data_offset;    // data offset (TCP only)

    u_char  flags;          // flags (TCP only)
    u_short window_size;    // window size (TCP only)
    u_short checksum;       // checksum
    u_short urgent_pointer; // urgent pointer (TCP only)
};

// struct port_scan_info {
//     u_int ip;           // source IP address
//     int port_no;         // destination port number
//     int count;           // number of attempts
// };



#endif