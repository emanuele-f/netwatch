#
# netwatch
# (C) 2017-20 Emanuele Faranda
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

def isActiveDevice(metadata):
  return (time.time() - metadata["last_seen"]) <= MAX_TIME_TO_BE_INACTIVE 

def countActiveUserDevices(devices_list, meta_db):
  count = 0
  activity_count = 0

  for mac in devices_list:
    metadata = meta_db.query(mac)

    if metadata and isActiveDevice(metadata):
      count += 1
      mac_info = config.getDeviceInfo(mac)

      if mac_info and mac_info.get("trigger_activity"):
        activity_count += 1

  return count, activity_count

def getDevicesData(meta_db):
  res = []

  for mac, value in config.getConfiguredDevices().items():
    metadata = meta_db.query(mac)
    device_ip = "-"
    device_active = "false"
    devname = value["custom_name"]

    if metadata:
      if metadata["last_ip"]: device_ip = metadata["last_ip"]
      if metadata["last_seen"]: device_active = "true" if isActiveDevice(metadata) else "false"
      if metadata["name"] and not devname: devname = metadata["name"]

    res.append({
      "mac": mac,
      "name": devname,
      "user": config.getDeviceUser(mac) or "Others",
      "ip": device_ip,
      "active_ping": value["active_ping"],
      "trigger_activity": value.get("trigger_activity", False),
      "active": device_active,
      "policy": value.get("policy", "default"),
    })
  
  return res

def getUsersData(meta_db):
  res = []

  for username, value in config.getConfiguredUsers().items():
    num_active_devices, num_activity_devices = countActiveUserDevices(value["devices"], meta_db)

    res.append({
      "name": username,
      "icon": value.get("icon"),
      "active": "true" if num_activity_devices > 0 else "false",
      "num_active_devices": num_active_devices,
      "tot_devices": len(value["devices"]),
    })

  return res

# Returns: captive_portal|pass|block
def getDevicePolicy(mac):
  mac_info = config.getDeviceInfo(mac)

  if mac_info:
    policy = mac_info.get("policy", "default")

    if policy != "default":
      return(policy)

  # Default policy
  if config.getCaptivePortalEnabled():
    return "captive_portal"

  return "pass"
