#   Extracting meaningful info

We captured this 16 bytes raw data: 

```bash
    fa a5 d0 79 4c d3 00 41 0e e8 2e b7 86 dd 60 01
```

## Major classification

```bash
    EEthernet Header (14 bytes)
    → 6 bytes  dest MAC
    → 6 bytes  src MAC
    → 2 bytes  EtherType

    IP Header (20-60 bytes)
        → 1 byte   version + IHL
        → 1 byte   type of service
        → 2 bytes  total length
        → 2 bytes  identification
        → 2 bytes  flags + fragment offset
        → 1 byte   TTL
        → 1 byte   protocol (TCP=6, UDP=17, ICMP=1)
        → 2 bytes  checksum
        → 4 bytes  source IP
        → 4 bytes  destination IP

    TCP/UDP Header
        → 2 bytes  source port
        → 2 bytes  destination port
        → ...      (rest differs between TCP and UDP)

    Payload (encrypted 🔒)
        → actual data — we don't touch this
```


This is what it means :

```bash
    Dest MAC  : fa:a5:d0:79:40:d3   (initial 6 bytes) 
    Source MAC: 00:41:0e:e8:2e:b7
    Protocol  : IPv6   (86 dd)
    Ip_header : 6001
```

EtherType values are standardized:
```bash
    0x0800  →  IPv4
    0x86DD  →  IPv6
    0x0806  →  ARP
    0x8100  →  VLAN tagged frame
```


### The IP header structure has a problem though 

- Its size is not fixed — unlike Ethernet which is always 14 bytes.
- The IP header can be 20 to 60 bytes depending on options.
- So how do you know where it ends?
  
The first byte of the IP header tells you — it contains two things packed into one byte:
```bash
    first 4 bits  → IP version (4 or 6)
    last 4 bits   → IHL (Internet Header Length)
```