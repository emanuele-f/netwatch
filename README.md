# Netwatch

Netwatch is a tool to monitor the presence of the devices into a network.

Here is a list of features Netwatch provides:
- Active/passive devices monitoring
- Timeline data visualization of a specific time frame
- Group the devices into people to get a per-person presence timeline
- Automatically determine device name from network traffic
- Manually assign a name to a device mac address

In order to do its job, Netwatch uses a combination of passive and active scanning techniques.
Active scanning is only used as fallback method to verify a device presence when
passive scanning fails. It is nevertheless possible to disable active scanning on
a device basis or turn off periodic active scan to have a passive-only (stealth) solution.

# Dependecies

In order to run Netwatch, you will need to satisfy the following dependencies:

- python2
- python2-webpy
- python2-pysqlite
- python2-prctl
- python2-dev (for C modules compilation)

# Build

Netwatch is written in python but requires some C modules to implement the low
level stuff. Before running Netwatch you will need to execute the following commands:

```
cd c_modules
make
cd ..
```

# Run

After building the C modules, you can run netwatch with the following command:

```
sudo ./main.py
```

Root privileges privileges will be dropped to nobody:nobody as soon as the
required linux capabilities are set.

# Licence

Netwatch is under the GPL 3 license.

# TODO 0.1
- Integrate device arp scan
- Add no data view
- Setting to scan network periodically
- People configuration
- People timeline
- Handle about
- Handle login

# TODO 0.2
- Unknown devices filter
