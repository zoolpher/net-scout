#include <pcap.h>
#include <iostream>
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
    pcap_t* interface_handle = pcap_open_live("\\Device\\NPF_{C8347FE4-229C-4801-B51B-D73E3E28A8C6}", 65536, 1, 1000, errbuf);   
        // const char*  → interface name (the NPF_{GUID} one)
        // int          → snaplen - max bytes to capture per packet [0 to 65536]
        // int          → promisc - promiscuous mode (1=on, 0=off)
        // int          → timeout - read timeout in milliseconds (1000 —> 1 second)
        // char*        → errbuf - same error buffer as before

    if (interface_handle == NULL) {  
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
    struct pcap_pkthdr* header;     // contains timestamp + length of packet
    const u_char* raw_data;         // raw bytes of the packet itself
    int count = 0;                      // counts N0. of packets captured

    while (true) {   
        int interface_captured = pcap_next_ex(interface_handle, &header, &raw_data);  
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
            fprintf(stderr, "Error capturing packet: %s\n", pcap_geterr(interface_handle));
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
        cout<<"Packet length:             "<<header->len<<" bytes\n";
        cout<<"Length of portion present: "<<header->caplen<<" bytes\n";
        cout<<"Timestamp:                 "<<header->ts.tv_sec<<" s || "<<header->ts.tv_usec<<" us\n";
        cout<<"Raw data (first 16 bytes): ";
        for (int i = 0; i < 16 && i < header->caplen; i++) {
            printf("%02x ", raw_data[i]);
        }
        cout<<"\n-------------------------------------------------------------------------------\n\n";
    }
    cout<<"Finished capturing packets.\n";
    cout<<"Total packets captured: "<<count<<"\n\n";
    
    
    return 0;
}