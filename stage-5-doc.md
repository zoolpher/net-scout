# Network Traffic Metadata Analyzer

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
| Stage 5 | SNI parsing from TLS handshakes | ✅ Complete |

---

## What Stage 5 Does

### TLS Client Hello Detection
Identifies TLS handshake packets by checking 5 conditions in order before touching any payload data. Only packets passing all 5 checks are processed for SNI extraction.

### SNI Field Extraction
Navigates the TLS record and handshake layers byte by byte — skipping variable-length fields (session ID, cipher suites, compression methods) — to reach the extensions section where the SNI field lives.

### Domain Name Logging
Extracts and prints the exact domain name your machine is connecting to from encrypted HTTPS traffic — without decrypting a single byte of payload.

### QUIC Limitation (Honest Engineering)
YouTube and other Google services use QUIC (UDP port 443) instead of TCP — so their TLS handshakes are not captured by this tool. This is expected behavior since the BPF filter targets TCP only. Sites using standard TCP + TLS (Reddit, GitHub, etc.) are captured correctly.

---

## How TLS SNI Parsing Works

When your browser connects to an HTTPS site, before encryption kicks in it sends a **TLS Client Hello** packet containing the SNI field — the domain name in plaintext:

```
Browser → "Hey server, I want to talk to reddit.com" → Server
                              ↑
                        SNI field — sent in plaintext
                        before any encryption begins
```

This is why ISPs, firewalls, and parental controls know which HTTPS sites you visit even without decrypting traffic.

---

## 5-Step Detection Filter

```
1. EtherType == 0x0800      → IPv4 packet          (BPF filter handles this)
2. IP protocol == 6         → TCP only              (ip_header->protocol == 6)
3. Dest port == 443         → HTTPS traffic         (ntohs(tcp->dest_port) == 443)
4. payload[0] == 0x16       → TLS record marker
5. payload[5] == 0x01       → Client Hello marker
```

Only if ALL 5 pass → proceed to SNI extraction.

---

## TLS Packet Structure

```
BYTE 0        → TLS content type     (0x16 = handshake)
BYTE 1-2      → TLS version
BYTE 3-4      → TLS record length
BYTE 5        → Handshake type       (0x01 = Client Hello)
BYTE 6-8      → Handshake length
BYTE 9-10     → Client version
BYTE 11-42    → Random bytes         (always exactly 32 bytes)
BYTE 43       → Session ID length    (variable)
BYTE 43+      → Session ID           (skip)
...           → Cipher suites length (2 bytes)
...           → Cipher suites        (skip)
...           → Compression length   (1 byte)
...           → Compression methods  (skip)
...           → Extensions length    (2 bytes)
...           → Extensions           ← SNI lives here (type 0x0000)
```

---

## Navigating to the SNI Field

Because session ID, cipher suites, and compression methods are all variable length — the extensions section cannot be reached with a hardcoded offset. Each variable field must be skipped explicitly:

```cpp
int pos = 43;

// skip session ID
u_char session_id_len = payload[pos];
pos += 1 + session_id_len;

// skip cipher suites
u_short cipher_len = (payload[pos] << 8) | payload[pos + 1];
pos += 2 + cipher_len;

// skip compression methods
u_char compression_len = payload[pos];
pos += 1 + compression_len;

// skip extensions length field
pos += 2;

// NOW at extensions — loop to find SNI (type 0x0000)
```

---

## TCP Header Size — Why It Matters

TCP header size is variable — just like IP header. The **Data Offset** field (byte 12 of the TCP header) stores the length:

```
src port     (2 bytes)
dest port    (2 bytes)
sequence num (4 bytes)
ack num      (4 bytes)
data offset  (1 byte)   ← upper 4 bits = header length in 32-bit words
```

```cpp
int tcp_size = (tcp_header->data_offset >> 4) * 4;
```

So payload starts at:
```
payload = raw_data + 14 + ip_size + tcp_size
                   ↑eth    ↑ip       ↑tcp
```

And payload length:
```
payload_len = header->len - 14 - ip_size - tcp_size
```

---

## Core Code Structure

```cpp
string parse_sni(const u_char* payload, int payload_len,
                 IPv4Header* ip_header, TcpUdpHeader* tcp_udp_header) {

    if (ip_header->protocol == 6 &&
        ntohs(tcp_udp_header->dest_port) == 443 &&
        payload_len > 5 &&
        payload[0] == 0x16 &&
        payload[5] == 0x01) {

        int pos = 43;
        u_char session_id_len = payload[pos];
        pos += 1 + session_id_len;

        u_short cipher_len = (payload[pos] << 8) | payload[pos + 1];
        pos += 2 + cipher_len;

        u_char compression_len = payload[pos];
        pos += 1 + compression_len;
        pos += 2;

        while (pos < payload_len) {
            if (pos + 4 > payload_len) break;
            u_short ext_type = (payload[pos] << 8) | payload[pos + 1];
            u_short ext_len  = (payload[pos + 2] << 8) | payload[pos + 3];

            if (ext_type == 0x00) {
                int sni_pos      = pos + 4;
                int sni_list_len = (payload[sni_pos] << 8) | payload[sni_pos + 1];
                int sni_name_pos = sni_pos + 2;

                while (sni_name_pos < sni_pos + 2 + sni_list_len) {
                    u_char  name_type = payload[sni_name_pos];
                    u_short name_len  = (payload[sni_name_pos + 1] << 8) | payload[sni_name_pos + 2];

                    if (name_type == 0x00) {
                        return string((char*)(payload + sni_name_pos + 3), name_len);
                    }
                    sni_name_pos += 3 + name_len;
                }
            }
            pos += 4 + ext_len;
        }
    }
    return "";
}
```

---

## Sample Output

```
SNI: r.reddit.com
SNI: telemetry.individual.githubcopilot.com
SNI: api.github.com
SNI: ocsp.digicert.com
```

---

## File Structure

```
project/
├── main.cpp        // capture loop + BPF filter + payload extraction
├── headers.h       // EthernetHeader, IpHeader, TcpUdpHeader structs
├── parser.h        // function declarations
├── parser.cpp      // get_ether_type(), get_app_name(), detect_port_scan(), parse_sni()
└── compile.bat     // g++ main.cpp parser.cpp -o output ...
```

---

## Tech Stack

- **Language:** C++17
- **Packet capture:** Npcap SDK (WinPcap API compatible)
- **Compiler:** MinGW-W64 / G++ 15.2
- **Filtering:** BPF filter — IPv4/TCP only (`"ip"`)
- **TLS parsing:** Manual byte-level navigation — no external TLS library
- **Platform:** Windows 10 / 11

---
