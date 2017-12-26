#!/bin/env python2

import socket, struct

def deviceToKey(device):
  return "".join(device.upper().split(":"))

def keyToDevice(key):
  return ":".join([key[i:i+2] for i in range(0, len(key), 2)])

def ip2long(ip):
  packedIP = socket.inet_aton(ip)
  return struct.unpack("!L", packedIP)[0]

def long2ip(l):
  if l == None: return None
  return socket.inet_ntoa(struct.pack('!L', l))
