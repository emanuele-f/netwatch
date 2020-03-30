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

import sys
import argparse
import logging
import signal, os
import time, datetime
import errno
import subprocess
import re
import config
from queue import Empty as QueueEmpty

TIME_SLOT = 60
REMAINING_BEFORE_POKE = 20
MESSAGE_CHECK_INTERVAL = 1
MAX_CHECK_BEFORE_FORCED_KILL = 10

LOG_LEVEL = logging.DEBUG
# LOG_LEVEL = logging.INFO

# ------------------------------------------------------------------------------

running = True
log = None
presence_db = None
meta_db = None
scanner_msgqueue = None

# Host which where active during the last time slot
prev_hosts = {}

# Host which are active during this time slot
next_hosts = {}

manager = None

# ------------------------------------------------------------------------------

class HostInfo():
  def __init__(self, mac, ip, last_seen, name=None):
    self.mac = mac
    self.ip = ip
    self.first_seen = last_seen
    self.last_seen = last_seen
    self.name = name

  def update(self, last_seen, name=None):
    self.last_seen = last_seen
    if name: self.name = name

class MessageParser():
  def __init__(self, msg):
    self.msg = msg
    self.last_idx = 0

  def nextField(self):
    idx = self.msg.find(FIFO_FIELD_DELIMITER, self.last_idx)

    if idx != -1:
      val = self.msg[self.last_idx:idx]
      self.last_idx = idx + len(FIFO_FIELD_DELIMITER)
      return val
    elif self.last_idx != len(self.msg):
      val = self.msg[self.last_idx:]
      self.last_idx = len(self.msg)
      return val
    return None

# ------------------------------------------------------------------------------

def initLogging():
  global log
  log = logging.getLogger('netwatch')
  log.setLevel(LOG_LEVEL)
  ch = logging.StreamHandler()
  ch.setLevel(LOG_LEVEL)
  ch.setFormatter(logging.Formatter('%(name)s[%(levelname)s] %(message)s'))
  log.addHandler(ch)

def sigHandler(signum, frame):
  global running
  global terminating

  if running != False:
    running = False
    print("Terminating...")
  else:
    print("Ok, leaving now")
    exit(1)

def initSignals():
  # NOTE: The main thread will be the only one to receive signals 
  signal.signal(signal.SIGINT, sigHandler)
  signal.signal(signal.SIGTERM, sigHandler)
  signal.signal(signal.SIGHUP, sigHandler)

# ------------------------------------------------------------------------------

def handleHost(mac, ip, seen_tstamp, host_name):
  global prev_hosts
  global next_hosts

  try:
    host = next_hosts[mac]
    host.update(seen_tstamp, host_name)
  except KeyError:
    try:
      host = prev_hosts[mac]
      host.update(seen_tstamp)
    except KeyError:
      host = HostInfo(mac, ip, seen_tstamp, host_name)
      log.info("[+]" + mac)

  next_hosts[mac] = host

def datetimeToTimestamp(dt):
  return int((time.mktime(dt.timetuple()) + dt.microsecond/1000000.0))

def insertHostsDataPoint(time_ref):
  global presence_db
  global meta_db
  global next_hosts

  devices = next_hosts.keys()
  log.debug("Insert datapoint: @" + str(time_ref) + ": " + str(len(devices)) + " devices")
  presence_db.insert(time_ref, devices)

  for host in next_hosts.values():
    meta_db.update(host.mac, int(host.last_seen), name=host.name, ip=host.ip)

def guessMainInterface():
  output = subprocess.check_output(['ip', '-4', 'route', 'list', '0/0'])

  if output:
    parts = output.decode("ascii").split()
    is_next = False

    for part in parts:
      if part == "dev":
        is_next = True
      elif is_next:
        return part

  return ""

def mainLoop():
  global running
  global prev_hosts
  global next_hosts

  now = int(time.time())
  prev_slot = now - (now % TIME_SLOT)
  next_slot = prev_slot + TIME_SLOT
  poke_time = next_slot - REMAINING_BEFORE_POKE
  poke_started = False

  while running:
    now = int(time.time())

    if now >= next_slot:
      # Remove old jobs
      if scanner_msgqueue:
        while not scanner_msgqueue.empty():
          try:
            scanner_msgqueue.get(False)
          except QueueEmpty:
            break

      insertHostsDataPoint(prev_slot)
      prev_hosts = next_hosts
      next_hosts = {}
      prev_slot = now - (now % TIME_SLOT)
      next_slot = prev_slot + TIME_SLOT
      poke_time = next_slot - REMAINING_BEFORE_POKE
      poke_started = False
    elif not poke_started and now >= poke_time:
      config.reload()

      if config.getPeriodicDiscoveryEnabled():
        if scanner_msgqueue:
          scanner_msgqueue.put("net_scan")
          log.debug("Peridoc ARP scan queued")
      else:
        for host in prev_hosts:
          try:
            h = next_hosts[host]
          except KeyError:
            max_time = next_slot - now - 1
            if (max_time >= 5) and (config.getDeviceProbeEnabled(prev_hosts[host].mac)):
              host = prev_hosts[host].ip
              if scanner_msgqueue:
                scanner_msgqueue.put(host)
                log.debug("Host " + host + " ARP scan queued")
      poke_started = True

    for message in manager.getMessages():
      handleHost(message.mac, message.ip, message.seen_tstamp, message.host_name)

    now = int(time.time())

    if now < next_slot:
      # TODO use blocking queue wait instead
      seconds = min(next_slot, now + MESSAGE_CHECK_INTERVAL) - now
      time.sleep(seconds)

def dropPrivileges(drop_user, drop_group):
  if os.getuid() != 0:
    print("You have not root privileges")
    exit(1)

  log.debug("Setting up required capabilities: " + ",".join(priv_utils.REQUIRED_CAPABILITIES))
  priv_utils.setup_permitted_capabilities()

  log.info("Dropping provileges to %s:%s ..." % (drop_user, drop_group))
  priv_utils.drop_privileges(drop_user, drop_group)

if __name__ == "__main__":
  import utils.privs as priv_utils

  initLogging()

  network_interface = guessMainInterface()

  parser = argparse.ArgumentParser()
  parser.add_argument('-u', dest="user", default="root", help='user:group to drop privileges to (default: do not drop privileges)')
  parser.add_argument('-i', dest="interface", default=network_interface, help='network interface to monitor (default: ' + network_interface + ')')
  parser.add_argument('-p', dest="passive", action='store_true', default=False, help="run in passive mode (do not send probes)")

  args = parser.parse_args(sys.argv[1:])

  if args.interface == "":
    log.error("Cannot determine main network interface, please specify the -i option")
    exit(1)

  if not ":" in args.user:
    drop_user = args.user
    drop_group = args.user
  else:
    drop_user, drop_group = args.user.split(":")

  if (drop_user != "root") and (drop_group != "root"):
    dropPrivileges(drop_user, drop_group)
  else:
    log.warning("Privileges will *not* be dropped, this could be dangerous! Use the '-u' option instead.")

  # Create data directory
  if not os.path.isdir("data"):      
    try:
      os.mkdir("data")
    except OSError:
      log.error("Could not create the data directory")
      exit(1)

  log.debug("Loading modules...")

  from utils.jobs import JobsManager
  from packets_reader import PacketsReaderJob
  from arp_scanner import ARPScannerJob
  from presence_db import PresenceDB
  from webserver import WebServerJob
  from meta_db import MetaDB

  log.debug("Initializing database...")
  presence_db = PresenceDB()
  meta_db = MetaDB()

  log.info("Starting startup jobs...")
  manager = JobsManager({
    "interface": args.interface,
  })

  log.debug("Starting packets reader...")
  manager.runJob(PacketsReaderJob())

  if not args.passive:
    log.debug("Starting ARP scanner...")
    scanner_msgqueue = manager.newQueue()
    manager.runJob(ARPScannerJob(), (scanner_msgqueue,))
  else:
    log.info("Ignoring ARP scanner in passive mode")

  log.debug("Starting web server...")
  manager.runJob(WebServerJob())

  log.info("Running main loop...")
  initSignals()

  try:
    mainLoop()
  except Exception as e:
    log.exception("Unexpected error")

  log.info("Main loop terminated, waiting for jobs termination...")
  manager.terminate()

  # Terminate the remaining processes
  i = 0
  while manager.getRunning():
    time.sleep(1)
    i = i + 1

    if i >= MAX_CHECK_BEFORE_FORCED_KILL:
      log.error("Some jobs do not stop, killing them now!")
      manager.kill()
      break
