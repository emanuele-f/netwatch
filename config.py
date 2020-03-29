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

import json
import errno

CONFIG_FILE = "data/config.json"
DEVICES_CONFIG_SECTION = "devices"
USERS_CONFIG_SECTION = "users"
GLOBAL_CONFG_SECTION = "global"

data = None

def _getInitialConfig():
  data = {
    DEVICES_CONFIG_SECTION: {},
    USERS_CONFIG_SECTION: {},
    GLOBAL_CONFG_SECTION: {
      "periodic_discovery": True,
    },
  }
  return data

def _loadData(force_reload = False):
  global data

  if not data or force_reload:
    data = None

    try:
      data = json.load(open(CONFIG_FILE))
    except IOError as err:
      if err.errno == errno.ENOENT:
        data = _getInitialConfig()
      else:
        raise

    macs_upper = {}

    for mac, mac_data in data[DEVICES_CONFIG_SECTION].items():
      macs_upper[mac.upper()] = mac_data

    data[DEVICES_CONFIG_SECTION] = macs_upper
    data[USERS_CONFIG_SECTION] = data.get(USERS_CONFIG_SECTION, {})
  return data

def _writeData(data):
  with open(CONFIG_FILE, 'w') as outfile:
    json.dump(data, outfile, indent=4, sort_keys=True, ensure_ascii=False)
  return True

# Returns True on success, False on failure
def _writeConfigNode(root, key, value, overwrite=True):
  data = _loadData()

  if not overwrite and key in data[root]:
    return False

  data[root][key] = value

  _writeData(data)
  return True

def _usersRemoveDevice(mac):
  for user, value in data[USERS_CONFIG_SECTION].items():
    if mac in value["devices"]:
      value["devices"].remove(mac)

def _userAddDevice(user, mac):
  value = data[USERS_CONFIG_SECTION][user]

  if not mac in value["devices"]:
    value["devices"].append(mac)

def getDeviceUser(mac):
  for user, value in data[USERS_CONFIG_SECTION].items():
    if mac in value["devices"]:
      return user
  return None

def addDevice(mac, custom_name, ping_device, user, trigger_activity, overwrite=False):
  data = _loadData()
  mac = mac.upper()

  if (not overwrite) and (mac in data[DEVICES_CONFIG_SECTION]):
    # device exists
    return False

  if user and not data[USERS_CONFIG_SECTION].get(user):
    # No such user
    return False

  _usersRemoveDevice(mac)

  data[DEVICES_CONFIG_SECTION][mac] = {
    "custom_name": custom_name,
    "active_ping": ping_device,
    "trigger_activity": trigger_activity,
  }

  if user:
    _userAddDevice(user, mac)

  return _writeData(data)

def deleteDevice(mac):
  data = _loadData()
  if not mac in data[DEVICES_CONFIG_SECTION]:
    return False

  value = data[DEVICES_CONFIG_SECTION].pop(mac)
  _usersRemoveDevice(mac)

  return _writeData(data)

def getConfiguredDevices():
  data = _loadData()
  return data[DEVICES_CONFIG_SECTION]

def getDeviceInfo(mac):
  data = _loadData()

  if mac in data[DEVICES_CONFIG_SECTION]:
    return data[DEVICES_CONFIG_SECTION][mac]

  return None

def addUser(username, avatar, old_username):
  data = _loadData()

  if (old_username != username) and (username in data[USERS_CONFIG_SECTION]):
    # user exists
    return False

  if old_username and (not old_username in data[USERS_CONFIG_SECTION]):    # old user does not exists
    return False

  user = None

  if old_username:
    user = data[USERS_CONFIG_SECTION].pop(old_username)
    user["icon"] = avatar
  else:
    user = {
      "icon": avatar,
      "devices": [],
    }

  data[USERS_CONFIG_SECTION][username] = user
  return _writeData(data)

def deleteUser(username):
  data = _loadData()
  if not username in data[USERS_CONFIG_SECTION]:
    return False

  data[USERS_CONFIG_SECTION].pop(username)
  return _writeData(data)

def getConfiguredUsers():
  data = _loadData()
  return data[USERS_CONFIG_SECTION]

def setPeriodicDiscoveryEnabled(enabled):
  data = _loadData()
  data[GLOBAL_CONFG_SECTION]["periodic_discovery"] = enabled
  return _writeData(data)

def getPeriodicDiscoveryEnabled():
  data = _loadData()
  return data[GLOBAL_CONFG_SECTION]["periodic_discovery"]

def getDeviceProbeEnabled(mac):
  try:
    return data[DEVICES_CONFIG_SECTION][mac]["active_ping"]
  except KeyError:
    return False

def reload():
  _loadData(True)
