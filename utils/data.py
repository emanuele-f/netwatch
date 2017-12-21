import time, datetime

import config

def getDevicesData():
  res = []

  for mac, value in config.getConfiguredDevices().iteritems():
    device_ip = "192.168.1.1" # TODO mongodb
    device_active = "true" # TODO mongodb

    res.append({
      "mac": mac,
      "name": value["custom_name"],
      "ip": device_ip,
      "active_ping": value["active_ping"],
      "active": device_active,
    })
  
  return res
