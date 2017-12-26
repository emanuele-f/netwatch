#!/bin/env python2
import web
from presence_db import PresenceDB
from meta_db import MetaDB
from utils.jobs import Job
from utils.data import getDevicesData
from utils.timeutils import makeEndTimestamp
import time
import config
import json
import threading

# web.config.debug = False
TEMPLATES = 'html/'
WEB_PORT = 8000
template_render = web.template.render(TEMPLATES, base='layout')

class MyApplication(web.application):
  def run(self, port=WEB_PORT, *middleware):
    func = self.wsgifunc(*middleware)
    return web.httpserver.runsimple(func, ('0.0.0.0', port))

def sendJsonData(data):
  web.header('Content-Type', 'application/json')
  return json.dumps(data, ensure_ascii=True)

def resToMinTime(res):
  if res == "1M":
    return 86400*31
  elif res == "24h":
    return 86400
  elif res == "1h":
    return 240
  else:
    return 10

class timeline:
  def GET(self):
    params = web.input()

    # TODO handle now
    timestamp = "now"
    resolution = "1m"

    try:
      timestamp = params.ts
      resolution = params.res
    except AttributeError:
      pass

    presence_db = PresenceDB()
    meta_db = MetaDB()
    ts_start = None
    ts_end = None

    if timestamp == "now":
      ts_end = time.time()
      ts_start = ts_end - 20 * 60
    else:
      ts_start = int(timestamp)
      ts_end = makeEndTimestamp(ts_start, resolution)

    presence_data = presence_db.query(ts_start, ts_end, resolution=resolution)
    configured_devices = config.getConfiguredDevices()
    min_time = resToMinTime(resolution)

    data = []
    for device, intervals in presence_data.iteritems():
      name = device

      if device in configured_devices:
        name = configured_devices[device]["custom_name"]
      else:
        meta = meta_db.query(device)

        if meta and meta["name"]:
          name = meta["name"]

      for interval in intervals:
        data.append((name, "", interval[0], interval[1], device))

    data.sort()

    return template_render.timeline(json.dumps(data, ensure_ascii=True), ts_start, ts_end, resolution, min_time)

class devices:
  def GET(self):
    return template_render.devices()

  def POST(self):
    data = web.input()
    action = data.action
    mac = data.mac
    overwrite = False

    if (action == "add") or (action == "edit"):
      if action == "edit":
        overwrite = True

      custom_name = data.custom_name
      active_ping = False

      # Optional
      try:
        active_ping = data.active_ping and True
      except AttributeError: pass

      config.addDevice(mac, custom_name, active_ping, overwrite=overwrite)
    elif action == "delete":
      config.deleteDevice(mac)

    raise web.seeother('/devices')

class devices_json:
  def GET(self):
    meta_db = MetaDB()
    return sendJsonData(getDevicesData(meta_db))

class WebServerJob(Job):
  def __init__(self):
    urls = (
      '/', 'timeline',
      '/devices', 'devices',
      '/data/devices.json', 'devices_json',
    )

    super(WebServerJob, self).__init__("web_server", self.run)
    self.stop_checker_thread = None
    self.app = MyApplication(urls, globals())

  # This is necessary since we cannot call self.app.stop from another process
  def _checkTermination(self):
    self.waitTermination()
    self.app.stop()

  def run(self, *args):
    self.stop_checker_thread = threading.Thread(target=self._checkTermination, args=())
    self.stop_checker_thread.start()
    self.app.run()
    self.stop_checker_thread.join()

if __name__ == "__main__":
  WebServerJob().run()
