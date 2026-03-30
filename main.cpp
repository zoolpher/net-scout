#include <pcap.h>

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
        
        printf("%s\n", d->name);     
    }
    

    //--------------------------
    // It free that list after
    //--------------------------
    pcap_freealldevs(alldevs);      


    return 0;
}