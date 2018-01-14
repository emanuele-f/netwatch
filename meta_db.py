#!/bin/env python2
#
# netwatch
# (C) 2017-18 Emanuele Faranda
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sqlite3
from utils.db import deviceToKey, keyToDevice, ip2long, long2ip

META_DB = "meta.db"

class MetaDB():
  def __init__(self):
    self.conn = sqlite3.connect(META_DB)
    self.cursor = self.conn.cursor()
    self._initTable()

  def _initTable(self):
    self.cursor.execute("""CREATE TABLE IF NOT EXISTS meta (mac CHARACTER(12) NOT NULL, last_seen INTEGER NOT NULL, last_ip INTEGER, name TEXT, PRIMARY KEY (mac))""")
    self.conn.commit()

  def update(self, mac, tstamp, name=None, ip=None):
    device_key = deviceToKey(mac)

    # first insert minimal info
    q = "INSERT INTO meta (mac, last_seen) SELECT ?, 0 WHERE NOT EXISTS(SELECT 1 FROM meta WHERE mac = ?) "
    params = [device_key, device_key]
    # print(q, params)
    self.cursor.execute(q, params)

    # actual update
    fields = ["last_seen = ?"]
    values = [tstamp]

    if ip:
      fields.append("last_ip = ?")
      values.append(ip2long(ip))

    if name:
      fields.append("name = ?")
      values.append(name)

    q = "UPDATE meta SET " + ", ".join(fields) + " WHERE mac = ?"
    values.append(device_key)
    # print(q, values)

    self.cursor.execute(q, values)
    self.conn.commit()

  def query(self, mac):
    q = "SELECT * FROM meta WHERE mac = ?"
    params = [deviceToKey(mac), ]
    # print(q, params)
    res = self.cursor.execute(q, params).fetchall()

    if not res or len(res) != 1:
      return None

    res = res[0]

    return {
      "mac": keyToDevice(res[0]),
      "last_seen": int(res[1]),
      "last_ip": long2ip(res[2]),
      "name": res[3],
    }

if __name__ == "__main__":
  import time
  tstamp = int(time.time())

  meta = MetaDB()
  meta.update("11:22:33:44:55:66", tstamp, name="Checco")
  meta.update("11:22:33:44:55:66", tstamp)
  meta.update("11:22:33:44:55:66", tstamp, ip="192.168.1.1")
  meta.update("22:22:33:44:55:66", tstamp)

  res = meta.query("22:22:33:44:55:66")
  assert(res["name"] == None)
  assert(res["last_seen"] == tstamp)
  res = meta.query("11:22:33:44:55:66")
  assert(res["mac"] == "11:22:33:44:55:66")
  assert(res["name"] == "Checco")
  assert(res["last_ip"] == "192.168.1.1")
