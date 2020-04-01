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
import pickle
import threading
import multiprocessing

# web.config.debug = False
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

class WebServerJob(Job):
  def __init__(self):
    # Manual termination not working. Also tried
    # https://github.com/Pylons/webtest/blob/af67b92c40d29dc9f4d7b0a6f5742b263fb2a227/tests/test_http.py
    # without luck. For now just kill the server brutally.
    super(WebServerJob, self).__init__("web_server", self.run, force_kill=True)

    self.web_msgqueue = None
    self.app = Flask("Netwatch",
      template_folder = './html',
      static_url_path = "/static")

    self.app.route('/', methods=['GET'])(self.GET_Timeline)
    self.app.route('/static/<path:path>', methods=['GET'])(self.GET_Static)
    self.app.route('/devices', methods=['GET'])(self.GET_Devices)
    self.app.route('/devices', methods=['POST'])(self.POST_Devices)
    self.app.route('/data/devices.json', methods=['GET'])(self.GET_Devices_JSON)
    self.app.route('/people', methods=['GET'])(self.GET_People)
    self.app.route('/people', methods=['POST'])(self.POST_People)
    self.app.route('/data/users.json', methods=['GET'])(self.GET_People_JSON)
    self.app.route('/settings', methods=['GET'])(self.GET_Settings)
    self.app.route('/settings', methods=['POST'])(self.POST_Settings)
    self.app.route('/about', methods=['GET'])(self.GET_About)

  def request_get_mode(self):
    mode = request.args.get('mode', "home")

    if not mode in ["home", "unknown"]:
      mode = "home"

    return(mode)

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
    mode = self.request_get_mode()
    return render_template('devices.html', config=config, mode=mode)

  def GET_Devices_JSON(self):
    mode = self.request_get_mode()

    if mode == "home":
      # Configured devices
      meta_db = MetaDB()
      return jsonify(getDevicesData(meta_db))
    else:
      self.web_msgqueue[0].send("get_active_devices")

      # Avoid infinite wait
      has_message = self.web_msgqueue[0].poll(10)

      if not has_message:
        return jsonify([])

      active_devices = pickle.loads(self.web_msgqueue[0].recv())
      rv = []

      for mac, hostinfo in active_devices.items():
        rv.append({
          "mac": mac,
          "name": hostinfo.name,
          "ip": hostinfo.ip,
          "first_seen": int(hostinfo.first_seen),
          "last_seen": int(hostinfo.last_seen),
        })

      return jsonify(rv)

  def POST_Devices(self):
    action = request.form.get('action')
    mac = request.form.get('mac')
    overwrite = False
    user = ""

    if (action == "add") or (action == "edit"):
      if action == "edit":
        overwrite = True

      custom_name = request.form.get('custom_name')
      user = request.form.get('user', None)
      active_ping = False
      trigger_activity = False

      # Optional
      active_ping = request.form.get('active_ping') and True
      trigger_activity = request.form.get('trigger_activity') and True

      config.addDevice(mac, custom_name, active_ping, user, trigger_activity, overwrite=overwrite)
    elif action == "delete":
      config.deleteDevice(mac)

    return redirect(url_for('GET_Devices'), code=303)

  def GET_People(self):
    return render_template('people.html')

  def GET_People_JSON(self):
    meta_db = MetaDB()
    return jsonify(getUsersData(meta_db))

  def POST_People(self):
    action = request.form.get('action')
    username = request.form.get('username')
    old_username = None

    if (action == "add") or (action == "edit"):
      avatar = request.form.get('avatar')

      if action == "edit":
        old_username = request.form.get('old_username')

      config.addUser(username, avatar, old_username)
    elif action == "delete":
      config.deleteUser(username)

    return redirect(url_for('GET_People'), code=303)

  def GET_About(self):
    return render_template('about.html')

  def GET_Settings(self):
    return render_template('settings.html', config=config)

  def POST_Settings(self):
    periodic_discovery = request.form.get('periodic_discovery') and True or False

    config.setPeriodicDiscoveryEnabled(periodic_discovery)

    return redirect(url_for('GET_Settings'), code=303)

  def run(self, _, web_msgqueue):
    self.web_msgqueue = web_msgqueue
    waitress.serve(self.app, port=WEB_PORT, threads=8)

if __name__ == "__main__":
  WebServerJob().run()
