import json
import errno

CONFIG_FILE = "config.json"
DEVICES_CONFIG_SECTION = "devices"

def _getInitialConfig():
  data = {
    DEVICES_CONFIG_SECTION: {},
  }
  return data

def _loadData():
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
