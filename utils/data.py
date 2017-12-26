import time, datetime

import config

MAX_TIME_TO_BE_INACTIVE = 300

def getDevicesData(meta_db):
  res = []

  for mac, value in config.getConfiguredDevices().iteritems():
    metadata = meta_db.query(mac)
    device_ip = "-"
    device_active = "false"
    devname = value["custom_name"]

    if metadata:
      if metadata["last_ip"]: device_ip = metadata["last_ip"]
      if metadata["last_seen"]: device_active = "true" if (time.time() - metadata["last_seen"]) <= MAX_TIME_TO_BE_INACTIVE else "false"
      if metadata["name"] and not devname: devname = metadata["name"]

    res.append({
      "mac": mac,
      "name": devname,
      "ip": device_ip,
      "active_ping": value["active_ping"],
      "active": device_active,
    })
  
  return res
