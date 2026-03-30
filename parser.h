#ifndef PARSER_H
#define PARSER_H

#include <pcap.h>
#include <string>

using namespace std;


//--------------------- STAGE 3 ---------------------
// Extracting meaningful info from raw bytes
string get_ether_type(u_short eth_type);

string get_app_name(u_short eth_type);




#endif