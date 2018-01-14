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
