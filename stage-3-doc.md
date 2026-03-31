#   Network Traffic Metadata Analyzer

> Real-time packet capture + anomaly detection — no payload inspection  
> `C++` · `Npcap` · `MinGW-W64` · `Windows`

---

## Build Progress

| Stage | Description | Status |
|-------|-------------|--------|
| Stage 1 | Interface enumeration | ✅ Complete |
| Stage 2 | Packet capture loop | ✅ Complete |
| Stage 3 | Ethernet / IP / TCP header parsing + app identification | ✅ Complete |
| Stage 4 | Anomaly detection — port scan detection | 🔲 Pending |
| Stage 5 | SNI parsing from TLS handshakes | 🔲 Pending |

---

## What Stage 3 Does

### Ethernet Header Parsing
Casts the first 14 bytes of every raw packet onto an `EthernetHeader` struct — instantly extracting source MAC, destination MAC, and EtherType without any loops or string operations.

### BPF Filter — IPv4 Only
Applies a Berkeley Packet Filter (`"ip"`) via `pcap_compile()` + `pcap_setfilter()` before the capture loop. Npcap drops all non-IPv4 packets at the driver level — only IPv4 reaches your code.

### IP Header Parsing
Casts bytes 14 onwards onto an `IpHeader` struct — extracting source IP, destination IP, TTL, and protocol. Handles variable IP header length using the IHL field (`version_ihl & 0x0F) * 4`).

### TCP/UDP Header Parsing
Casts bytes at `14 + ip_header_size` onto a `TcpUdpHeader` struct — extracting source and destination port numbers. Port numbers are converted from network byte order using `ntohs()`.

### App Identification by Port
`get_app_name()` maps destination port numbers to human-readable service names — so instead of `443` you see `HTTPS`, instead of `53` you see `DNS`.

---

## Packet Structure Parsed

```
┌─────────────────────────────┐
│      ETHERNET HEADER        │  14 bytes total
│  dest MAC (6) · src MAC (6) │
│  EtherType (2)              │  0x0800=IPv4 · 0x86DD=IPv6 · 0x0806=ARP
├─────────────────────────────┤
│         IP HEADER           │  20–60 bytes (variable)
│  version+IHL (1) · TOS (1) │
│  total length (2) · ID (2)  │
│  flags (2) · TTL (1)        │
│  protocol (1) · checksum (2)│
│  src IP (4) · dest IP (4)   │
├─────────────────────────────┤
│       TCP/UDP HEADER        │
│  src port (2) · dest port(2)│  ← app identified here
├─────────────────────────────┤
│          PAYLOAD            │  🔒 never touched
└─────────────────────────────┘
```

---

## How Struct Casting Works

Instead of looping through bytes manually, a struct is overlaid directly onto raw memory:

```cpp
// The struct maps exactly onto the bytes
struct EthernetHeader {
    u_char  dest_mac[6];   // bytes 0–5
    u_char  src_mac[6];    // bytes 6–11
    u_short ether_type;    // bytes 12–13
};

// Cast raw pointer — zero copying, zero looping
EthernetHeader* eth = (EthernetHeader*) raw_data;

// Access fields directly
printf("%02x:%02x:%02x:%02x:%02x:%02x",
    eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
    eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
```

---

## Core Code Structure

```cpp
// --- Ethernet ---
EthernetHeader* eth = (EthernetHeader*) raw_data;
cout << "EtherType : " << get_ether_type(ntohs(eth->ether_type)) << "\n";

// --- IP ---
IpHeader* ip = (IpHeader*)(raw_data + 14);
int ip_size = (ip->version_ihl & 0x0F) * 4;
cout << "Src IP : " << inet_ntoa(*(struct in_addr*)&ip->src_ip) << "\n";
cout << "Dst IP : " << inet_ntoa(*(struct in_addr*)&ip->dest_ip) << "\n";

// --- TCP/UDP ---
TcpUdpHeader* tcp = (TcpUdpHeader*)(raw_data + 14 + ip_size);
cout << "Src Port : " << ntohs(tcp->src_port) << "\n";
cout << "Dst Port : " << get_app_name(ntohs(tcp->dest_port)) << "\n";
```

---

## Byte Order — Why `ntohs()` and `ntohl()`

Network packets use **big-endian** byte order. x86 CPUs use **little-endian**. Without conversion, `0x0800` reads as `0x0008` — wrong value, wrong EtherType.

| Function | Converts |
|----------|----------|
| `ntohs()` | 2-byte values (ports, EtherType) |
| `ntohl()` | 4-byte values (IP addresses) |
| `inet_ntoa()` | 4-byte IP → `"192.168.1.1"` string |

---

## App Identification by Port

```cpp
string get_app_name(int port) {
    switch (port) {
        case 80:   return "HTTP";
        case 443:  return "HTTPS";
        case 53:   return "DNS";
        case 22:   return "SSH";
        case 3306: return "MySQL";
        case 5228: return "Google Services";
        default:   return "Unknown";
    }
}
```

---

## Sample Output

```
-------------------------------------------------------------------------------
Packet length             : 110 bytes
Timestamp                 : 1774856328 s || 460838 us
Source MAC                : fa:a5:d0:79:4c:d3
Destination MAC           : 00:41:0e:e8:2e:b7
EtherType                 : IPv4
Source IP                 : 192.168.1.5
Destination IP            : 20.51.80.213
Source Port               : 56350
Destination Port          : HTTPS
-------------------------------------------------------------------------------
```

---

## File Structure

```
project/
├── main.cpp        // capture loop + BPF filter
├── headers.h       // EthernetHeader, IpHeader, TcpUdpHeader structs
├── parser.h        // function declarations
├── parser.cpp      // get_ether_type(), get_app_name()
└── compile.bat     // g++ main.cpp parser.cpp -o output ...
```

---

## Tech Stack

- **Language:** C++17
- **Packet capture:** Npcap SDK (WinPcap API compatible)
- **Compiler:** MinGW-W64 / G++ 15.2
- **Filtering:** BPF filter — IPv4 only (`"ip"`)
- **Byte order:** `ntohs()` / `inet_ntoa()` for correct value reading
- **Platform:** Windows 10 / 11

---

## Up Next — Stage 4

**Anomaly Detection** — track unique destination ports per source IP using an `unordered_map`. When any IP probes more than 10 distinct ports, fire a port scan alert with the full list of probed services.

---

## Commit History

```
feat: enumerate all network interfaces using pcap_findalldevs
feat: open interface and capture live packets in continuous loop
feat: parse ethernet, IP, and TCP/UDP headers with app identification
```