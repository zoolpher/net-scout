#   Network Traffic Metadata Analyzer

> Real-time packet capture + anomaly detection — no payload inspection  
> `C++` · `Npcap` · `MinGW-W64` · `Windows`

---

## Build Progress

| Stage | Description | Status |
|-------|-------------|--------|
| Stage 1 | Interface enumeration | ✅ Complete |
| Stage 2 | Packet capture loop | 🔲 Pending |
| Stage 3 | Ethernet / IP / TCP header parsing + app identification | 🔲 Pending |
| Stage 4 | Anomaly detection — port scan detection | 🔲 Pending |
| Stage 5 | SNI parsing from TLS handshakes | 🔲 Pending |

---

## What Stage 1 Does

### Network Interface Enumeration
Uses Npcap's `pcap_findalldevs()` to query the OS at the kernel level and retrieve all available network interfaces on the machine — including physical adapters, virtual adapters, and the loopback interface.

### Interface Listing
Prints every interface's internal device name (Windows GUID format) and its human-readable description so the correct capture interface can be identified before any packet capture begins.

### Foundation Setup
Establishes the Npcap SDK linkage, compiler flags, and project file structure that all subsequent stages build on.

---

## How It Works

```
Program starts
     ↓
pcap_findalldevs() queries Npcap driver
     ↓
Npcap talks to Windows kernel
     ↓
Returns linked list of all network interfaces
     ↓
Loop through list → print name + description
     ↓
pcap_freealldevs() — clean up memory
```

### Core Code Structure

```cpp
pcap_if_t* alldevs;
char errbuf[PCAP_ERRBUF_SIZE];

pcap_findalldevs(&alldevs, errbuf);

for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
    cout << d->name << "\n";
    cout << d->description << "\n";
}

pcap_freealldevs(alldevs);
```

---

## Sample Output

```
1. \Device\NPF_{4B6A3C1D-89F2-4E7A-B3D1-1234567890AB}
   Description: Intel(R) Wi-Fi 6 AX201 160MHz

2. \Device\NPF_{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
   Description: Realtek PCIe GbE Family Controller

3. \Device\NPF_Loopback
   Description: Adapter for loopback traffic capture
```

---

## Understanding the Output

### What is `\Device\NPF_{GUID}`?
Every network adapter on Windows is assigned a **GUID** (Globally Unique Identifier) — a 128-bit number generated when the driver is installed. It never changes unless the driver is reinstalled.

Npcap prepends `\Device\NPF_` to it:
- `NPF` = Network Packet Filter — Npcap's kernel driver name
- The GUID maps to actual hardware in the Windows Registry at `HKLM\SYSTEM\CurrentControlSet\Control\Class\{GUID}`

### What is `\Device\NPF_Loopback`?
A virtual interface that captures traffic where your machine talks to itself. All traffic to `127.0.0.1` passes through here.

---

## File Structure

```
project/
├── main.cpp        // interface enumeration logic
└── compile.bat     // g++ main.cpp -o output ...
```

---

## Compiler Setup

```bat
g++ main.cpp -o output ^
  -I"D:\software\npcap\npcap-sdk\Include" ^
  -L"D:\software\npcap\npcap-sdk\Lib\x64" ^
  -lwpcap -lws2_32
```

---

## Tech Stack

- **Language:** C++17
- **Packet capture:** Npcap SDK (WinPcap API compatible)
- **Compiler:** MinGW-W64 / G++ 15.2
- **Platform:** Windows 10 / 11

---

## Up Next — Stage 2

**Live Packet Capture** — open a selected interface and capture real packets flowing through it in a continuous loop, printing length and timestamp for each one.

---

## Commit History

```
feat: enumerate all network interfaces using pcap_findalldevs
```