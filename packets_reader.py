#!/usr/bin/python3
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
    handle = pkt_reader.open_capture_dev(self.options["interface"], 1000, "broadcast or arp", False)

    while self.isRunning():
      info = pkt_reader.read_packet_info(handle)

      if info:
        name = None
        if "name" in info:
          name = info["name"]
        self.handleHost(info["mac"], info["ip"], name)

    pkt_reader.close_capture_dev(handle)
