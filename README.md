#Dependecies

- python2
- python2-webpy
- python2-pysqlite
- python2-prctl

# TODO
# 1.0
- Device info edit
- Handle device ping
- Time range selector
- Fix time range: must show start also if no data
- Fix single point range hidden
- Arp scanner
- Last ip show
- Handle status
- Unknown devices
- Handle login
- Setting to ping unknown devices
- Minimal caching on the queue writes
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
