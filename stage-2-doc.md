#   Raw Data (16 byte raw data)

┌─────────────────────────────┐
│         ETHERNET HEADER     │  ← first 14 bytes
├─────────────────────────────┤
│           IP HEADER         │  ← starts at byte 15
├─────────────────────────────┤
│          TCP/UDP HEADER     │
├─────────────────────────────┤
│            PAYLOAD          │
└─────────────────────────────┘

### The raw data we got :

```bash
    00 41 0e e8 2e b7 fa a5 d0 79 4c d3 86 dd 6b 81
```

- 00 41 0e e8 2e b7  → destination MAC address (6 bytes)
- fa a5 d0 79 4c d3  → source MAC address (6 bytes)
- 86 dd              → EtherType (2 bytes) — what protocol is inside
- 6b 81              → first 2 bytes of IP header


🧠 That 86 dd is interesting — that's not random.
EtherType values are standardized:
```bash
    08 00  → IPv4
    86 DD  → IPv6
    08 06  → ARP
```
So your packet is IPv6 