#!/bin/env python2

import logging
import signal, os
import time, datetime
import errno
import subprocess
import re
from ctypes import c_char_p

# TODO make it configurable, allow to keep privileges
PRIVILEGE_DROP_USER = "emanuele"
PRIVILEGE_DROP_GROUP = "emanuele"

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

# Host which where active during the last time slot
prev_hosts = {}

# Host which are active during this time slot
next_hosts = {}

# Hosts actively poked
poking_hosts = {}

manager = None

# ------------------------------------------------------------------------------

class HostInfo():
  def __init__(self, mac, ip, last_seen):
    self.mac = mac
    self.ip = ip
    self.first_seen = last_seen
    self.last_seen = last_seen

  def update(self, last_seen):
    self.last_seen = last_seen

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

  # TODO handle host_name

  try:
    host = next_hosts[mac]
    host.update(seen_tstamp)
  except KeyError:
    try:
      host = prev_hosts[mac]
      host.update(seen_tstamp)
    except KeyError:
      host = HostInfo(mac, ip, seen_tstamp)
      log.info("[+]" + mac)

  next_hosts[mac] = host

def datetimeToTimestamp(dt):
  return int((time.mktime(dt.timetuple()) + dt.microsecond/1000000.0))

def insertHostsDataPoint(time_ref):
  global presence_db
  global next_hosts

  devices = next_hosts.keys()
  log.debug("Insert datapoint: @" + str(time_ref) + ": " + str(len(devices)) + " devices")
  presence_db.insert(time_ref, devices)

  # TODO
  #DB_COLLECTION_HOSTS_METADATA

def poke_host(host, max_seconds, rv_value):
  NUM_PINGS = 5
  PINGS_INTERVAL = 5

  args = ["ping", "-q", "-w", str(max_seconds), "-i", str(PINGS_INTERVAL), "-c", str(NUM_PINGS), host]
  log.debug("Executing: " + " ".join(args))
  output = ""

  try:
    output = subprocess.check_output(args)
  except subprocess.CalledProcessError as e:
    if e.returncode == 0:
      raise

  match = re.search('(\d+) received', output)

  if match and len(match.groups(0)):
    if match.groups(0)[0] != "0":
      rv_value.value = str(int(time.time()))

  rv_value.value = ""

def startPoke(host, ip, max_seconds):
  global poking_hosts

  if not host in poking_hosts:
    log.info("Poking host " + host + "...")
    # rv_value = manager.Value(c_char_p, "")
    # process = multiprocessing.Process(target=poke_host, args=(ip, max_seconds, rv_value))
    # process.start()

    # Start poking process
    # poking_hosts[host] = {
      # "rv_value": rv_value,
      # "process": process,
    # }

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
      # Stop old poking hosts
      for host, poking in poking_hosts.iteritems():
        process = poking["process"]

        if process.is_alive():
          log.warning("Poking process for host " + host + " is alive, killing")
          process.terminate()
        else:
          if not host in next_hosts and poking["rv_value"].value:
            host_info = prev_hosts[host]
            host_info.update(int(poking["rv_value"].value))
            next_hosts[host] = host_info
            log.debug("Ping successful: " + host)
        process.join()

      insertHostsDataPoint(prev_slot)
      prev_hosts = next_hosts
      next_hosts = {}
      prev_slot = now - (now % TIME_SLOT)
      next_slot = prev_slot + TIME_SLOT
      poke_time = next_slot - REMAINING_BEFORE_POKE
      poke_started = False
    elif not poke_started and now >= poke_time:
      for host in prev_hosts:
        try:
          h = next_hosts[host]
        except KeyError:
          max_time = next_slot - now - 1
          if max_time >= 5:
            startPoke(host, prev_hosts[host].ip, max_time)
      poke_started = True

    for messages in manager.getMessages():
      for message in messages:
        handleHost(message.mac, message.ip, message.seen_tstamp, message.host_name)

    now = int(time.time())

    if now < next_slot:
      # TODO use blocking queue wait instead
      seconds = min(next_slot, now + MESSAGE_CHECK_INTERVAL) - now
      time.sleep(seconds)

def dropPrivileges():
  if os.getuid() != 0:
    print("You have not root privileges")
    exit(1)

  log.debug("Setting up required capabilities: " + ",".join(priv_utils.REQUIRED_CAPABILITIES))
  priv_utils.setup_permitted_capabilities()

  log.info("Dropping provileges to %s:%s ..." % (PRIVILEGE_DROP_USER, PRIVILEGE_DROP_GROUP))
  priv_utils.drop_privileges(PRIVILEGE_DROP_USER, PRIVILEGE_DROP_GROUP)

if __name__ == "__main__":
  import utils.privs as priv_utils

  initLogging()
  dropPrivileges()

  log.debug("Loading modules...")

  from utils.jobs import JobsManager
  from packets_reader import PacketsReaderJob
  from presence_db import PresenceDB
  from webserver import WebServerJob

  log.debug("Initializing database...")
  presence_db = PresenceDB()

  log.info("Starting startup jobs...")
  manager = JobsManager()

  log.debug("Starting packets reader...")
  manager.runJob(PacketsReaderJob())
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
