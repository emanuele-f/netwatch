#!/usr/bin/python2

import time
import os

from utils.jobs import Job
from utils.privs import acquire_capabilities
import c_modules.pkt_reader as pkt_reader

from message import Message

SNIFF_TIMEOUT = 1

class PacketsReaderJob(Job):
  def __init__(self):
    super(PacketsReaderJob, self).__init__("PacketsReaderJob", self.task)
    self.msg_queue = None

  def handleHost(self, host_mac, host_ip, host_name):
    if host_mac != "00:00:00:00:00:00":
      # TODO handle queue full
      msg = Message(host_mac, host_ip, time.time())
      if host_name:
        msg.host_name = host_name
      self.msg_queue.put(msg)

  def task(self, msg_queue):
    # Acquire capabilities to capture packets
    acquire_capabilities()
    self.msg_queue = msg_queue

    # TODO make interface configurable
    handle = pkt_reader.open_capture_dev("wlan0", 1000, "broadcast or arp")

    while self.isRunning():
      info = pkt_reader.read_packet_info(handle)

      if info:
        name = None
        if "name" in info:
          name = info["name"]
        self.handleHost(info["mac"], info["ip"], name)

    pkt_reader.close_capture_dev(handle)
