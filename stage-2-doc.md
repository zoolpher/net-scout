#   Network Traffic Metadata Analyzer

> Real-time packet capture + anomaly detection — no payload inspection  
> `C++` · `Npcap` · `MinGW-W64` · `Windows`

---

## Build Progress

| Stage | Description | Status |
|-------|-------------|--------|
| Stage 1 | Interface enumeration | ✅ Complete |
| Stage 2 | Packet capture loop | ✅ Complete |
| Stage 3 | Ethernet / IP / TCP header parsing + app identification | 🔲 Pending |
| Stage 4 | Anomaly detection — port scan detection | 🔲 Pending |
| Stage 5 | SNI parsing from TLS handshakes | 🔲 Pending |

---

## What Stage 2 Does

### Live Interface Opening
Uses `pcap_open_live()` to open the correct WiFi interface for packet capture — identified from the Stage 1 interface list. The interface handle is reused across all subsequent captures without reopening.

### Continuous Packet Capture Loop
Runs a `while(true)` loop calling `pcap_next_ex()` on every iteration — capturing one real live packet per call. Runs indefinitely until timeout or error.

### Packet Metadata Printing
For every captured packet, prints the total length, captured length, timestamp (seconds + microseconds), and first 16 raw bytes in hex — confirming real data is being received from the network.

### Graceful Error Handling
Handles all four return states of `pcap_next_ex()` — success, timeout, error, and end-of-file — with appropriate messages and clean exits.

---

## How It Works

```
pcap_open_live() → open WiFi interface (once, outside loop)
     ↓
while(true)
     ↓
pcap_next_ex() → grab next live packet
     ↓
return 1  → packet captured → print metadata
return 0  → timeout → exit cleanly
return -1 → error → print errbuf → exit
return -2 → savefile EOF → exit
     ↓
loop again
```

### Core Code Structure

```cpp
pcap_t* interface_handle = pcap_open_live(
    "\\Device\\NPF_{your-guid}",
    65536,    // snaplen — capture full packet
    0,        // promiscuous mode off
    0,        // timeout = 0 (wait forever)
    errbuf
);

struct pcap_pkthdr* header;
const u_char* raw_data;
int count = 0;

while (true) {
    int result = pcap_next_ex(interface_handle, &header, &raw_data);

    if (result == 1) {
        cout << ++count << " Packet captured\n";
        cout << "Length    : " << header->len << " bytes\n";
        cout << "Timestamp : " << header->ts.tv_sec << "s\n";
        // print first 16 raw bytes
        for (int i = 0; i < 16; i++)
            printf("%02x ", raw_data[i]);
    }
    else if (result == 0)  { cout << "Timeout\n"; return 0; }
    else if (result == -1) { fprintf(stderr, "%s\n", pcap_geterr(interface_handle)); return 0; }
    else if (result == -2) { cout << "EOF\n"; return 0; }
}
```

---

## Sample Output

```
1 Packet captured
-------------------------------------------------------------------------------
Packet length             : 110 bytes
Length of portion present : 110 bytes
Timestamp                 : 1774856328 s || 460838 us
Raw data (first 16 bytes) : fa a5 d0 79 4c d3 00 41 0e e8 2e b7 86 dd 60 01
-------------------------------------------------------------------------------
2 Packet captured
...
188 Packet captured
Timeout expired while waiting for a packet.
Finished capturing packets.
Total packets captured: 188
```

---

## Key Concepts

### `pcap_open_live()` vs `pcap_next_ex()`

| Function | Role |
|----------|------|
| `pcap_open_live()` | Opens the tap — called once |
| `pcap_next_ex()` | Puts a glass under it — called per packet |

### `pcap_pkthdr` fields

| Field | Meaning |
|-------|---------|
| `header->len` | Original packet length on the wire |
| `header->caplen` | Bytes actually captured (≤ len) |
| `header->ts.tv_sec` | Unix timestamp — seconds |
| `header->ts.tv_usec` | Microsecond precision |

### Why timeout = 0?
Setting timeout to `1000` (1 second) causes the program to exit if no packet arrives within that window. Setting it to `0` tells Npcap to wait indefinitely — the loop only exits on error or manual interrupt.

---

## File Structure

```
project/
├── main.cpp        // capture loop + packet metadata printing
└── compile.bat     // g++ main.cpp -o output ...
```

---

## Tech Stack

- **Language:** C++17
- **Packet capture:** Npcap SDK (WinPcap API compatible)
- **Compiler:** MinGW-W64 / G++ 15.2
- **Platform:** Windows 10 / 11

---

## Up Next — Stage 3

**Header Parsing** — parse those raw hex bytes into meaningful data: MAC addresses, IP addresses, port numbers, and app identification — all from metadata alone, zero payload inspection.

---

## Commit History

```
feat: enumerate all network interfaces using pcap_findalldevs
feat: open interface and capture live packets in continuous loop
```