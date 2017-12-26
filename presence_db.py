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

  def _getIntervals(self, devices_to_tstamp, interval_edge):
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
          if (point - interval_end) > interval_edge:
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

      devices_to_tstamp[device].append(int(tstamp))
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

  def query(self, tstamp_start, tstamp_end, device_filter=None, resolution=None):
    q = " FROM presence WHERE timestamp >= ? AND timestamp <= ?"
    time_what = "timestamp"
    params = [tstamp_start, tstamp_end]
    interval_edge = RESOLUTION

    if device_filter:
      q = q + " AND mac = ?"
      params.append(self._deviceToKey(device_filter))

    if resolution == "1h":
      q = q + " GROUP BY strftime('%H', datetime(timestamp, 'unixepoch')), mac"
      interval_edge = 3600
    elif resolution == "24h":
      time_what = "strftime('%s', strftime('%Y-%m-%d', timestamp, 'unixepoch'), 'utc')"
      q = q + " GROUP BY strftime('%m-%d', datetime(timestamp, 'unixepoch')), mac"
      interval_edge = 86400
    elif resolution == "1M":
      time_what = "strftime('%s', strftime('%Y-%m-01 00:00:00', timestamp, 'unixepoch'), 'utc')"
      q = q + " GROUP BY strftime('%Y-%m', datetime(timestamp, 'unixepoch')), mac"
      interval_edge = 2678400
    else:
      q = q + "GROUP BY timestamp, mac"

    what = time_what + ", mac"
    q = "SELECT " + what + q
    # print(q, params)

    res = self.cursor.execute(q, params)
    devices_to_tstamp = self._groupByDevice(res)
    # print(devices_to_tstamp)
    return self._getIntervals(devices_to_tstamp, interval_edge)

if __name__ == "__main__":
  import time
  tstamp = int(time.time())

  presence = PresenceDB()
  # presence.insert(1513444570, {
    # "aa:bb:cc:dd:ee:ff": 1,
  # })
  print(presence.query(int(time.time())-9600, int(time.time())))
  # print(presence.query(int(time.time())-9600, int(time.time()), "aa:bb:cc:dd:ee:ff"))
