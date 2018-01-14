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

import json
import errno

CONFIG_FILE = "config.json"
DEVICES_CONFIG_SECTION = "devices"
GLOBAL_CONFG_SECTION = "global"

data = None

def _getInitialConfig():
  data = {
    DEVICES_CONFIG_SECTION: {},
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

    for mac, mac_data in data[DEVICES_CONFIG_SECTION].iteritems():
      macs_upper[mac.upper()] = mac_data

    data[DEVICES_CONFIG_SECTION] = macs_upper
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

def addDevice(mac, custom_name, ping_device, overwrite=False):
  data = _loadData()

  if (not overwrite) and (mac in data[DEVICES_CONFIG_SECTION]):
    # device exists
    return False

  data[DEVICES_CONFIG_SECTION][mac] = {
    "custom_name": custom_name,
    "active_ping": ping_device,
  }

  return _writeData(data)

def deleteDevice(mac):
  data = _loadData()
  if not mac in data[DEVICES_CONFIG_SECTION]:
    return False

  data[DEVICES_CONFIG_SECTION].pop(mac)
  return _writeData(data)

def getConfiguredDevices():
  data = _loadData()
  return data[DEVICES_CONFIG_SECTION]

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
