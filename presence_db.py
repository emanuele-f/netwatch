#!/bin/env python2

import sqlite3

# TODO fixme
PRESENCE_DB = "/home/emanuele/Desktop/netwatch/presence.db"
RESOLUTION = 60

class PresenceDB():
  def __init__(self):
    self.conn = sqlite3.connect(PRESENCE_DB)
    self.cursor = self.conn.cursor()
    self._initTable()

  def _initTable(self):
    self.cursor.execute("""CREATE TABLE IF NOT EXISTS presence (timestamp INTEGER NOT NULL, mac CHARACTER(12) NOT NULL, PRIMARY KEY (timestamp, mac))""")
    self.cursor.execute("""CREATE INDEX IF NOT EXISTS idx_presence_mac ON presence (mac)""")
    self.cursor.execute("""CREATE INDEX IF NOT EXISTS idx_presence_timestamp ON presence (timestamp)""")
    self.conn.commit()

  def _getIntervals(self, devices_to_tstamp):
    hosts_intervals = {}

    for device, tstamps in devices_to_tstamp.iteritems():      
      interval_start = None
      interval_end = None
      intervals = []
      tstamps.sort()

      for point in tstamps:
        if not interval_start:
          interval_start = point
          interval_end = point
        else:
          if (point - interval_end) > RESOLUTION:
            if interval_end >= interval_start:
              intervals.append((interval_start, interval_end))
            interval_start = point
          interval_end = point

      if tstamps:
        intervals.append((interval_start, interval_end))
      hosts_intervals[device] = intervals

    return hosts_intervals

  def _groupByDevice(self, res):
    devices_to_tstamp = {}

    for row in res:
      tstamp, device_key = row
      device = self._keyToDevice(device_key)

      if not device in devices_to_tstamp:
        devices_to_tstamp[device] = []

      devices_to_tstamp[device].append(tstamp)
    return devices_to_tstamp

  def _deviceToKey(self, device):
    return "".join(device.upper().split(":"))

  def _keyToDevice(self, key):
    return ":".join([key[i:i+2] for i in range(0, len(key), 2)])

  def insert(self, tstamp, devices):
    for device in devices:
      device_key = self._deviceToKey(device)
      self.cursor.execute("INSERT INTO presence VALUES (?,?)", (tstamp, device_key))

    self.conn.commit()

  def query(self, tstamp_start, tstamp_end, device_filter=None):
    q = "SELECT * FROM presence WHERE timestamp >= ? AND timestamp <= ?"
    params = [tstamp_start, tstamp_end]

    if device_filter:
      q = q + " AND mac = ?"
      params.append(self._deviceToKey(device_filter))

    res = self.cursor.execute(q, params)
    devices_to_tstamp = self._groupByDevice(res)
    return self._getIntervals(devices_to_tstamp)

if __name__ == "__main__":
  import time
  tstamp = int(time.time())

  presence = PresenceDB()
  # presence.insert(1513444570, {
    # "aa:bb:cc:dd:ee:ff": 1,
  # })
  print(presence.query(int(time.time())-9600, int(time.time())))
  # print(presence.query(int(time.time())-9600, int(time.time()), "aa:bb:cc:dd:ee:ff"))
