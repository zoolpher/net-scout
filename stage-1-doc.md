#   GUIDs Globally Unique IDentifier


example:   {4B6A3C1D-89F2-4E7A-B3D1-1234567890AB}

- 128 bit number
- Generated when Windows installs a network driver
- Guaranteed to be unique across every machine on earth
- Never changes unless you reinstall the driver

### Why Windows uses them instead of simple names like eth0 on Linux:

Linux says → eth0, wlan0, lo — simple, human readable
Windows says → absolutely not 😭 here's a UUID from hell

Windows does this because:

- Multiple adapters of same type can exist
- Driver model needs stable unique references
- Registry maps GUIDs to actual hardware

### Where this GUID lives on your machine:

Registry → HKEY_LOCAL_MACHINE
            → SYSTEM
              → CurrentControlSet
                → Control
                  → Class
                    → {your GUID}

### Want to see your GUID mapped to your actual adapter name? Run this in terminal:

```bash
terminal command
>>> ipconfig /all
```