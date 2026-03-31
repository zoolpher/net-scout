# 🛡️ Network Traffic Metadata Analyzer

> Real-time packet capture + anomaly detection — no payload inspection  
> `C++` · `Npcap` · `MinGW-W64` · `Windows`

---

## What Is This?

A low-level network traffic analyzer built in C++ using the Npcap SDK. It captures live packets directly from your network interface at the driver level, parses Ethernet, IP, and TCP/UDP headers, detects port scan anomalies, and extracts domain names from encrypted HTTPS traffic — all without inspecting a single byte of payload content.

This is essentially a stripped-down Wireshark + IDS (Intrusion Detection System) built from scratch.

---

## How It Works

```
Network Interface (WiFi/Ethernet)
          ↓
     Npcap Driver          ← kernel-level capture
          ↓
   BPF Filter (IPv4)       ← drops non-IPv4 at driver level
          ↓
  Ethernet Header Parse    ← MAC addresses, EtherType
          ↓
    IP Header Parse        ← src/dest IP, protocol
          ↓
  TCP/UDP Header Parse     ← ports → app identification
          ↓
  ┌───────────────────┐
  │  Anomaly Detection │   ← port scan via unordered_map
  └───────────────────┘
          ↓
  ┌───────────────────┐
  │    SNI Parsing    │   ← domain names from TLS handshakes
  └───────────────────┘
```

---

## 🗺️ The Build Plan — 5 Stages

| Stage | Description | Status | Docs |
|-------|-------------|--------|------|
| Stage 1 | Setup Npcap + enumerate network interfaces | ✅ Complete | [stage-1-doc.md](stage-1-doc.md) |
| Stage 2 | Packet capture loop + raw packet metadata | ✅ Complete | [stage-2-doc.md](stage-2-doc.md) |
| Stage 3 | Parse Ethernet/IP/TCP headers + app identification by port | ✅ Complete | [stage-3-doc.md](stage-3-doc.md) |
| Stage 4 | Pattern analysis + port scan anomaly detection | ✅ Complete | [stage-4-doc.md](stage-4-doc.md) |
| Stage 5 | SNI parsing — extract domains from TLS handshakes | ✅ Complete | [stage-5-doc.md](stage-5-doc.md) |

---

## Key Features

- **Zero payload inspection** — only metadata is read, never message content
- **Live packet capture** — directly from WiFi/Ethernet at kernel level via Npcap
- **Header parsing** — Ethernet, IPv4, TCP/UDP decoded via struct casting
- **App identification** — port numbers mapped to service names (HTTPS, DNS, SSH, etc.)
- **Port scan detection** — `unordered_map` tracks unique ports per source IP, alerts at threshold
- **SNI extraction** — reads domain names from TLS Client Hello before encryption kicks in

---

## Packet Structure Parsed

```
┌─────────────────────────────┐
│      ETHERNET HEADER        │  14 bytes
│  dest MAC · src MAC · type  │
├─────────────────────────────┤
│         IP HEADER           │  20–60 bytes (variable)
│  src IP · dest IP · TTL     │
├─────────────────────────────┤
│       TCP/UDP HEADER        │
│  src port · dest port       │  ← app identified here
├─────────────────────────────┤
│          PAYLOAD            │  🔒 never touched
│    TLS Client Hello →       │  ← SNI extracted here
└─────────────────────────────┘
```

---

## Sample Output

```
142 Packet captured successfully :)
-------------------------------------------------------------------------------
Packet length            : 199 bytes
Timestamp                : 1774949032 s || 867350 us
Source MAC               : fa:a5:d0:79:4c:d3
Destination MAC          : 00:41:0e:e8:2e:b7
EtherType                : IPv4
Source IP                : 192.168.43.191
Destination IP           : 151.101.1.140
Source Port              : Unknown
Destination Port         : HTTPS
SNI                      : r.reddit.com
-------------------------------------------------------------------------------

🚨 PORT SCAN DETECTED
Suspicious IP  : 192.168.1.100
Ports probed   : 31
22   → SSH
80   → HTTP
443  → HTTPS
...
```

---

## File Structure

```
project/
├── main.cpp        // capture loop + BPF filter + payload extraction
├── headers.h       // EthernetHeader, IpHeader, TcpUdpHeader structs
├── parser.h        // function declarations
├── parser.cpp      // all parsing + detection functions
└── compile.bat     // g++ main.cpp parser.cpp -o output ...
```

---

## Tech Stack

- **Language:** C++17
- **Packet capture:** Npcap SDK (WinPcap API compatible)
- **Compiler:** MinGW-W64 / G++ 15.2
- **Filtering:** BPF — IPv4/TCP only
- **Anomaly detection:** `unordered_map` + `set` — O(1) per packet
- **TLS parsing:** Manual byte-level navigation — no external library
- **Platform:** Windows 10 / 11

---

## Commit History

```
Stage 1 and initialization
Stage 2 feat: capture-real-time-packets
Stage 3 feat: parse ethernet, IP, and TCP/UDP headers with app identification
Stage 4 feat: add port scan detection with unordered_map tracking
Stage 4 feat: print all probed ports with app names on port scan detection
update all markdown files
Stage 5 feat: extract SNI domain names from TLS Client Hello packets
update Readme.md
```