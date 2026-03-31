#include <pcap.h>
#include <iostream>

#include <windows.h>
#include <string>

#include "headers.h"
#include "parser.h"

using namespace std;




int main() {


    //=============================================================
    //                           STAGE 1  
    // 1. Include Npcap headers
    // 2. Find all network interfaces on your machine
    // 3. Print their names
    // 4. That's it — just list them
    //=============================================================
    
    
    pcap_if_t* alldevs;             // Pointer to the list of network interfaces
    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to hold error messages
    
    
    //---------------------------------------------------------------
    // Function that finds interfaces
    // - returns linked list of interfaces in alldevs 
    // - returns -1 on error and fills errbuf with error message
    //---------------------------------------------------------------
    int interfaces = pcap_findalldevs(&alldevs, errbuf);        


    //-----------------------------------
    // Check if there was an error
    //-----------------------------------
    if (interfaces == -1) {          
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 0;
    }

    
    //------------------------------------------------------------
    // Loop through the list of interfaces
    // Print the name of each interface
    //------------------------------------------------------------
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {  
        // It prints << GUIDs Globally Unique IDentifier >>
        
        printf("%s  |   %s\n", d->name, d->description ? d->description : "No description available");     
    }
    
    
    //--------------------------
    // It free that list after
    //--------------------------
    pcap_freealldevs(alldevs);    
    
    
    
    //=============================================================
    //                           STAGE 2
    // 1. Open your WiFi interface (the NPF_{GUID} one)
    // 2. Capture ONE packet
    // 3. Print its length
    // 4. Close the interface  
    //        pcap_open_live()   → opens an interface for capturing
    //        pcap_next_ex()     → grabs the next packet
    //        pcap_close()       → closes the interface when done
    //=============================================================

    //---------------------------------------------------------------
    // Opens the interface for capturing
    //
    // pcap_open_live()  → opens a DOOR to the interface
    //                 returns a HANDLE (like a file handle)
    //                 does NOT capture anything yet
    //---------------------------------------------------------------

    const char* interface_name = "\\Device\\NPF_{C8347FE4-229C-4801-B51B-D73E3E28A8C6}";
    int snaplen = 65536;            
    int promisc = 1;                    
    int timeout = 0;                 
    pcap_t* interface_handler = pcap_open_live(interface_name, snaplen, promisc, timeout, errbuf);   
        // const char*  → interface name (the NPF_{GUID} one)
        // int          → snaplen - max bytes to capture per packet [0 to 65536]
        // int          → promisc - promiscuous mode (1=on, 0=off)
        // int          → timeout - read timeout in milliseconds (1000 —> 1 second)
        // char*        → errbuf - same error buffer as before

    if (interface_handler == NULL) {  
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 0;
    }
    
    cout<<"\n\nInterface opened successfully for capturing :)\n\n";


    //--------------------------------------------------------------------
    // Grabs ONE packet
    // 
    // pcap_next_ex()    → actually reaches through that door
    //                     and grabs ONE packet
    //--------------------------------------------------------------------
    struct pcap_pkthdr* header;         // contains timestamp + length of packet
    const u_char* raw_data;             // raw bytes of the packet itself
    int count = 0;                      // counts N0. of packets captured
    
    
    
    //================================================================================
    //                          STAGE 3 
    //                 Extracting meaningful info 
    //
    // You'll parse those raw bytes into actual meaningful data:
    // - Extract source & destination MAC addresses
    // - Extract source & destination IP addresses
    // - Extract port(TCP/UDP) numbers → identify which app made the traffic        
    //================================================================================
    struct bpf_program filter_program;
    pcap_compile(interface_handler, &filter_program, "ip", 0, PCAP_NETMASK_UNKNOWN);  
    // compile the filter expression
    
    pcap_setfilter(interface_handler, &filter_program);                          
    // apply the compiled filter to the capture handle

   


    //---------------------------------------- stage 2 ------------------------------------------
    while (true) {   
        int interface_captured = pcap_next_ex(interface_handler, &header, &raw_data);  
            // pcap_t*              → the handle returned by pcap_open_live()
            // struct pcap_pkthdr** → pointer to packet header (we don't need it here)
            // const u_char**       → pointer to packet data (we don't need it here)

        if (interface_captured == 1) {
            cout<<++count<<" Packet captured successfully :)\n\n";
        }
        else if (interface_captured == 0) {
            cout<<"Timeout expired while waiting for a packet.\n\n";
            cout<<"Finished capturing packets.\n";
            cout<<"Total packets captured: "<<count<<"\n\n";
            return 0;
        }
        else if (interface_captured == -1) {
            fprintf(stderr, "Error capturing packet: %s\n", pcap_geterr(interface_handler));
            cout<<"Finished capturing packets.\n";
            cout<<"Total packets captured: "<<count<<"\n\n";
            return 0;
        }
        else if (interface_captured == -2) {
            cout<<"No more packets to read from the savefile.\n\n";
            cout<<"Finished capturing packets.\n";
            cout<<"Total packets captured: "<<count<<"\n\n";
            return 0;
        }

        cout<<"-------------------------------------------------------------------------------\n";
        cout<<"Packet length            : "<<header->len<<" bytes\n";
        cout<<"Length of portion present: "<<header->caplen<<" bytes\n";
        cout<<"Timestamp                : "<<header->ts.tv_sec<<" s || "<<header->ts.tv_usec<<" us\n";
        cout<<"Raw data (first 16 bytes):\n";
        
        //------------------------ stage 2 -----------------------------
        for (int i = 0; i < 16 && i < header->caplen; i++) {
            printf("%02x ", raw_data[i]);
        }
        cout<<"\n";

        //------------------------ stage 3 -----------------------------
        EthernetHeader* eth_header = (EthernetHeader*) raw_data;
        printf("Source mac add      : %02x:%02x:%02x:%02x:%02x:%02x  \n", eth_header->src_mac[0], eth_header->src_mac[1], eth_header->src_mac[2], eth_header->src_mac[3], eth_header->src_mac[4], eth_header->src_mac[5]);
        printf("Destination mac add : %02x:%02x:%02x:%02x:%02x:%02x \n", eth_header->dest_mac[0], eth_header->dest_mac[1], eth_header->dest_mac[2], eth_header->dest_mac[3], eth_header->dest_mac[4], eth_header->dest_mac[5]);
        printf("EtherType           : %s (0x%04x) \n", get_ether_type(ntohs(eth_header->ether_type)).c_str(), eth_header->ether_type);

        IPv4Header* ip_header = (IPv4Header*)(raw_data + 14);
        cout<<"Source IP add         : "<<inet_ntoa(*(struct in_addr*)&ip_header->src_ip)<<"\n";
        cout<<"Destination IP add    : "<<inet_ntoa(*(struct in_addr*)&ip_header->dest_ip)<<"\n";

        TcpUdpHeader *tcp_udp_header = (TcpUdpHeader*)(raw_data + 14 + ((ip_header->version_ihl & 0x0F) * 4));
        cout<<"Source port           : "<<get_app_name(ntohs(tcp_udp_header->src_port))<<"\n";
        cout<<"Destination port      : "<<get_app_name(ntohs(tcp_udp_header->dest_port));
        
        
        //==============================================================================
        //                                  STAGE 4 
        //              Finding Unusual Activity: Port Scanning Detection
        //==============================================================================
        detect_port_scan(ip_header, tcp_udp_header);
        // to store unique packets 
        // ip_addr : <port_visited, port_visited, port_visited, ...>
        
        
        
        //==============================================================================
        //                                  STAGE 5 
        //                    TLS SNI (Server Name Indication) Parser
        //==============================================================================
        
        // Calculate TCP header size and get to the payload
        u_char tcp_size = (tcp_udp_header->data_offset >> 4) * 4;
        
        // Calculate IP header size and get to the payload
        int ip_size = (ip_header->version_ihl & 0x0F) * 4;
        
        const u_char* payload = raw_data + 14 + ip_size + tcp_size;
        int payload_len = header->len - 14 - ip_size - tcp_size;
        
        string sni = parse_sni(payload, payload_len, ip_header, tcp_udp_header);
        if (!sni.empty()) {
            cout << "\nSNI: " << sni << "\n";
            Sleep(5000);  // 5000 milliseconds = 5 seconds
        }
        cout<<"\n-------------------------------------------------------------------------------\n\n";
         
    }
    cout<<"Finished capturing packets.\n";
    cout<<"Total packets captured: "<<count<<"\n\n";


   
    
    
    return 0;
}