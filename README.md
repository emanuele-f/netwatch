# Netwatch

Netwatch - a tool to monitor and manage the presence of the devices into a network.

![alt text](https://raw.githubusercontent.com/emanuele-f/netwatch/master/screenshots/devices_page.png)

Here is a list of features Netwatch provides:
- Active/passive devices monitoring
- Timeline data visualization of a specific time frame
- Group the devices into people to get a per-person presence timeline
- Automatically determine device name from network traffic
- Ability to block specific devices or to authenticate them via a Captive Portal

In order to do its job, Netwatch uses a combination of passive and active scanning techniques.
Active scanning is only used as fallback method to verify a device presence when
passive scanning fails. It is nevertheless possible to disable active scanning on
a device basis or turn off periodic active scan to have a passive-only (stealth) solution.

## Dependecies

In order to run Netwatch, you will need to satisfy the following dependencies:

- python3
- python3-flask
- python3-flask-httpauth
- python3-waitress
- python-pysqlite2
- python3-prctl
- libnftables-dev
- libpcap-dev
- python3-dev (for C modules compilation)

## Build

Netwatch is written in python but requires some C modules to implement the low
level stuff. Before running Netwatch you will need to execute the following commands:

```
cd c_modules
make
cd ..
```

## Run

After building the C modules, you can run netwatch with the following command:

```
sudo ./main.py
```

Note: you should add `-u user` option to drop the privileges to the specified user.

You can now visit the page http://127.0.0.1:8000/ from your browser to access the
Netwatch gui.

System wide installation is not curretly supported. You can modify the sample service file `packages/netwatch.service`
to run the program at startup.

## Authentication

netwatch supports the Basic HTTP Authentication. Credentials will be sent in plaintext! In order to enabled it,
create a `creds.txt` file in the netwatch directory with a single line `username:password`

## Licence

Netwatch is under the GPL 3 license.

## TODO 0.1
- Add no data view
- People timeline
