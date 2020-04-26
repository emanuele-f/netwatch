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

from flask import Flask, request, abort, redirect, Response, url_for, jsonify, render_template, send_from_directory
from utils.jobs import Job
from utils.privs import acquire_capabilities
from urllib.parse import urlencode
import c_modules.nft as nft
import waitress
import logging

CAPTIVE_PORT = 9000
DEFAULT_URL = "https://google.com"

# TODO unify with main.py
log = logging.getLogger('CaptivePortal')
log.setLevel(logging.DEBUG)

class CaptivePortalJob(Job):
  def __init__(self):
    # Manual termination not working. Also tried
    # https://github.com/Pylons/webtest/blob/af67b92c40d29dc9f4d7b0a6f5742b263fb2a227/tests/test_http.py
    # without luck. For now just kill the server brutally.
    super(CaptivePortalJob, self).__init__("captive_portal", self.run, force_kill=True)

    self.cp_eventsqueue = None
    self.app = Flask("Captive Portal",
      template_folder = './html',
      static_url_path = "/static")

    self.app.route('/favicon.ico', methods=['GET'])(self.NotFound)
    self.app.route('/login', methods=['GET'])(self.GET_Login)
    self.app.route('/login_ok', methods=['POST'])(self.POST_LoginOk)
    self.app.route('/login_ok', methods=['GET'])(self.GET_LoginOk)
    self.app.route('/static/<path:path>', methods=['GET'])(self.GET_Static)
    self.app.route('/<path:path>', methods=['GET'])(self.catch_all)
    self.app.route('/', methods=['GET'])(self.catch_all)

  def get_login_url(self, url):
    # NOTE: it is better to redirect to the host in order to avoid confusing
    # the client
    host = "%s:%d" % (self.captive_host, CAPTIVE_PORT)

    if url:
      return host + url_for('GET_Login') + "?" + urlencode({'url': url})
    else:
      return host + url_for('GET_Login')

  def GET_Static(self, path):
    return send_from_directory('js', path)

  def GET_Login(self):
    url = request.args.get("url")
    return render_template('captive_portal.html', url=url)

  def GET_LoginOk(self):
    #url = request.args.get("url")

    # Redirect to the original url if possible
    #if not url:

    # IMPORTANT: do not redirect to the original URL has the client may
    # reuse the original connection, which would be redirected back to the
    # login page
    url = DEFAULT_URL

    print("Will redirect to: " + url)
    return render_template('captive_portal_ok.html', url=url)

  def POST_LoginOk(self):
    username = request.form.get("username")
    password = request.form.get("password")
    success = False

    if username and password:
      log.info("Login: ip='%s' username='%s' password='%s'" % (request.remote_addr, username, password))
      # TODO
      success = True
      self.cp_eventsqueue[0].send(("auth_ok", request.remote_addr))

    if success:
      # Need to add the expection immediately, before redirecting the device
      # TODO: IP should be harvested when DHCP requests are seen, otherwill
      # the IP will be allowed forever
      nft.run("add element ip nat cp_auth_ok { %s }" % (request.remote_addr,))
      nft.run("add element ip filter cp_auth_ok { %s }" % (request.remote_addr,))

      return(self.GET_LoginOk())
    else:
      return redirect(self.get_login_url(url), code=303)

  def NotFound(self):
    abort(404)

  def catch_all(self, path='/'):
    #response = Response(html_data, 302, mimetype="text/html")
    #response.headers["Location"] = login_url
    #return response
    return redirect(self.get_login_url(request.url), code=302)

  def run(self, _, cp_eventsqueue):
    # Acquire capabilities to run nftables commands (nft)
    acquire_capabilities()

    # TODO get this globally instead of getting here/in packets_reader
    self.captive_host = "http://" + nft.get_iface_ip(self.options["interface"])
    self.cp_eventsqueue = cp_eventsqueue
    waitress.serve(self.app, port=CAPTIVE_PORT, threads=8)

if __name__ == "__main__":
  CaptivePortalJob().run()
