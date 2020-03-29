#!/bin/env python3
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
from flask import Flask, request, redirect, url_for, jsonify, render_template, send_from_directory
from presence_db import PresenceDB
from meta_db import MetaDB
from utils.jobs import Job
from utils.data import getDevicesData, getUsersData
from utils.timeutils import makeEndTimestamp
import waitress
import time
import config
import json
import threading
import multiprocessing

# web.config.debug = False
TEMPLATES = 'html/'
WEB_PORT = 8000

def resToMinTime(res):
  if res == "1M":
    return 86400*31
  elif res == "24h":
    return 86400
  elif res == "1h":
    return 240
  else:
    return 10

class people:
  def GET(self):
    return template_render.people()

  def POST(self):
    data = web.input()
    action = data.action
    username = data.username
    old_username = None

    if (action == "add") or (action == "edit"):
      avatar = data.avatar

      if action == "edit":
        old_username = data.old_username

      config.addUser(username, avatar, old_username)
    elif action == "delete":
      config.deleteUser(username)

    raise web.seeother('/people')

class settings:
  def GET(self):
    return template_render.settings(config)

  def POST(self):
    data = web.input()
    periodic_discovery = False

    try:
        periodic_discovery = data.periodic_discovery and True
    except AttributeError: pass

    config.setPeriodicDiscoveryEnabled(periodic_discovery)

    raise web.seeother('/settings')

class about:
  def GET(self):
    return template_render.about()

class users_json:
  def GET(self):
    meta_db = MetaDB()
    return jsonify(getUsersData(meta_db))

class WebServerJob(Job):
  def __init__(self):
    # TODO migrate
    urls = (
      '/people', 'people',
      '/settings', 'settings',
      '/about', 'about',
      '/data/users.json', 'users_json',
    )

    # Manual termination not working. Also tried
    # https://github.com/Pylons/webtest/blob/af67b92c40d29dc9f4d7b0a6f5742b263fb2a227/tests/test_http.py
    # without luck. For now just kill the server brutally.
    super(WebServerJob, self).__init__("web_server", self.run, force_kill=True)

    self.app = Flask("Netwatch",
      template_folder = TEMPLATES,
      static_url_path = "/static")

    self.app.route('/', methods=['GET'])(self.GET_Timeline)
    self.app.route('/devices', methods=['GET'])(self.GET_Devices)
    self.app.route('/devices', methods=['POST'])(self.POST_Devices)
    self.app.route('/data/devices.json', methods=['GET'])(self.GET_Devices_JSON)
    self.app.route('/<path:path>', methods=['GET'])(self.GET_Static)

  def GET_Static(self, path):
    return send_from_directory('js', path)

  def GET_Timeline(self):
    # TODO handle now
    timestamp = request.args.get('username', "now")
    resolution = request.args.get('password', "1m")

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
    for device, intervals in presence_data.items():
      name = device
      name_on_packet = ""

      meta = meta_db.query(device)

      if meta and meta["name"]:
        name_on_packet = meta["name"]

      if device in configured_devices:
        name = configured_devices[device]["custom_name"]
      elif name_on_packet:
        name = name_on_packet

      for interval in intervals:
        data.append((name, "", interval[0], interval[1], device, name_on_packet))

    data.sort()

    return render_template('timeline.html', intervals_data=json.dumps(data, ensure_ascii=True),
      timestamp=ts_start, timestamp_end=ts_end, resolution=resolution, chart_min_time=min_time)

  def GET_Devices(self):
    return render_template('devices.html', config=config)

  def GET_Devices_JSON(self):
    meta_db = MetaDB()
    return jsonify(getDevicesData(meta_db))

  def POST_Devices(self):
    action = request.form.get('action')
    mac = request.form.get('mac')
    overwrite = False
    user = ""

    if (action == "add") or (action == "edit"):
      if action == "edit":
        overwrite = True
        user = request.form.get('user')

      custom_name = request.form.get('custom_name')
      active_ping = False
      trigger_activity = False

      # Optional
      active_ping = request.form.get('active_ping') and True
      trigger_activity = request.form.get('trigger_activity') and True

      config.addDevice(mac, custom_name, active_ping, user, trigger_activity, overwrite=overwrite)
    elif action == "delete":
      config.deleteDevice(mac)

    return redirect(url_for('GET_Devices'), code=303)

  def run(self, *args):
    waitress.serve(self.app, port=WEB_PORT, threads=8)

if __name__ == "__main__":
  WebServerJob().run()
