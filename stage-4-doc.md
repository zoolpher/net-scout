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
| Stage 4 | Anomaly detection — port scan detection | ✅ Complete |
| Stage 5 | SNI parsing from TLS handshakes | 🔲 Pending |

---

## What Stage 4 Does

### Port Scan Detection
Tracks unique destination ports per source IP across all captured packets. When any single IP probes more than 10 distinct ports, an alert fires immediately with the full list of probed ports and their app names.

### Live Port Tracking
State persists across all packets using an `unordered_map` — no resets between captures. Every new packet updates the tracker in O(1) time.

### Named Port Reporting
On alert, dumps every probed port alongside its human-readable service name via `get_app_name()` — so output is immediately meaningful, not just raw numbers.

### Metadata Only
Zero payload inspection. Detection runs entirely on IP and port metadata — legally and ethically safe to run on your own network.

---

## Detection Logic

```
Packet arrives
     ↓
Extract src IP + dest port
     ↓
tracker[src_ip].insert(dest_port)   ← set auto-deduplicates
     ↓
size() > 10?
     ↓
YES → fire alert + dump all probed ports
NO  → continue silently
```

### Core Data Structure

```cpp
// src_ip → set of unique destination ports it has probed
unordered_map<string, set<int>> port_scan_tracker;

void detect_port_scan(IPv4Header* ip, TcpUdpHeader* tcp) {
    string src = inet_ntoa(*(struct in_addr*)&ip->src_ip);
    port_scan_tracker[src].insert(ntohs(tcp->dest_port));

    if (port_scan_tracker[src].size() > 10) {
        cout << "🚨 PORT SCAN DETECTED\n";
        cout << "Suspicious IP : " << src << "\n";
        cout << "Ports probed  : " << port_scan_tracker[src].size() << "\n";
        for (int port : port_scan_tracker[src]) {
            cout << port << " → " << get_app_name(port) << "\n";
        }
        Sleep(5000);
    }
}
```

---

## Sample Alert Output

```
🚨 PORT SCAN DETECTED
Suspicious IP  : 192.168.1.100
Ports probed   : 14

22   → SSH
80   → HTTP
443  → HTTPS
3306 → MySQL
8080 → HTTP-Alt
...
```

---

## File Structure

```
project/
├── main.cpp        // capture loop + BPF filter (IPv4 only)
├── headers.h       // EthernetHeader, IpHeader, TcpUdpHeader structs
├── parser.h        // function declarations
├── parser.cpp      // get_ether_type(), get_app_name(), detect_port_scan()
└── compile.bat     // g++ main.cpp parser.cpp -o output ...
```

---

## Packet Structure Parsed

```
┌─────────────────────────────┐
│      ETHERNET HEADER        │  14 bytes
│  dest MAC · src MAC · type  │
├─────────────────────────────┤
│         IP HEADER           │  20–60 bytes
│  src IP · dest IP · TTL     │
├─────────────────────────────┤
│       TCP/UDP HEADER        │
│  src port · dest port       │  ← app identified here
├─────────────────────────────┤
│          PAYLOAD            │  🔒 never touched
└─────────────────────────────┘
```

---

## Tech Stack

- **Language:** C++17
- **Packet capture:** Npcap SDK (WinPcap API compatible)
- **Compiler:** MinGW-W64 / G++ 15.2
- **Filtering:** BPF filter — IPv4 only (`"ip"`)
- **Anomaly detection:** `unordered_map` + `set` — O(1) per packet
- **Platform:** Windows 10 / 11

---

## Up Next — Stage 5

**SNI Parsing** — extract domain names from TLS Client Hello packets.

SNI (Server Name Indication) is transmitted in plaintext before TLS encryption kicks in. Your program will intercept this field and log which exact domains your machine is connecting to — without decrypting a single byte of payload.

This is how ISPs, firewalls, and parental controls know which HTTPS sites you visit.

---

## Commit History

```
feat: parse ethernet, IP, and TCP/UDP headers with app identification
feat: add port scan detection with unordered_map tracking
feat: print all probed ports with app names on port scan detection
```