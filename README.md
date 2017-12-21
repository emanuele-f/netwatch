#Dependecies

- python2
- python2-webpy
- python2-pysqlite
- python2-prctl

# TODO
# 1.0
- Map device mac to name
- Device info edit
- Handle device ping
- Time range selector
- Fix time range: must show start also if no data
- Last ip show
- Handle status
- Handle empty devices timeline
- Unknown devices
- Wrap into a single script
- Handle login
- Setting to ping unknown devices
- Handle DHCP name interpreter
- Minimal caching on the fifo writes
- People configuration
- People timeline
- Handle about

# C modules
The following C modules are provided:
  - `pkt_reader.c`: reads network packets from a network interface and extract device information

In order to compile them, you need to run:

```
cd c_modules
make
```

Python C library is required to build them.

# Run

`sudo ./main.py`

Root privileges are dropped to nobody:nobody as soon as the capabilities to capture from network
interfaces are set.
