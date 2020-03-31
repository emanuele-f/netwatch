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

# TODO
SPOOFING_ENABLED = False
SPOOFING_DEFAULT_SPOOF = False
SPOOFING_TIMEOUT = 1.0
SPOOFING_EXCEPTIONS = {}

class PacketsReaderJob(Job):
  def __init__(self):
    super(PacketsReaderJob, self).__init__("PacketsReaderJob", self.task)
    self.msg_queue = None

  def handleHost(self, host_mac, host_ip, host_name, now):
    if host_mac != "00:00:00:00:00:00":
      # TODO handle queue full
      msg = Message(host_mac, host_ip, now)
      if host_name:
        msg.host_name = host_name
      self.msg_queue.put(msg)

  def shouldSpoof(self, mac):
    if SPOOFING_ENABLED and (mac != self.gateway_mac) and \
        (mac != self.iface_mac) and (mac != "00:00:00:00:00:00"):
      is_exception = SPOOFING_EXCEPTIONS.get(mac)

      if((SPOOFING_DEFAULT_SPOOF and not is_exception) or
          (not SPOOFING_DEFAULT_SPOOF and is_exception)):
        return True

    return False

  def task(self, msg_queue):
    # Acquire capabilities to capture packets
    acquire_capabilities()
    self.msg_queue = msg_queue

    # TODO make interface configurable
    handle = pkt_reader.open_capture_dev(self.options["interface"], 1000, "broadcast or arp", False)
    self.gateway_mac = pkt_reader.get_gateway_mac(handle)
    self.iface_mac = pkt_reader.get_iface_mac(handle)

    if SPOOFING_ENABLED:
      print("[MAC: %s] Gateway %s (%s)" % (self.iface_mac, self.gateway_mac, pkt_reader.get_gateway_ip(handle)))

    macs_to_spoof = {} # TODO cleanup old
    last_request_spoof = 0

    while self.isRunning():
      info = pkt_reader.read_packet_info(handle)

      if info:
        name = info.get("name")
        mac = info["mac"]
        ip = info["ip"]
        now = time.time()

        self.handleHost(mac, ip, name, now)

        if self.shouldSpoof(mac):
          if(info.get("proto") == "ARP_REQ"):
            # Immediately spoof the reply
            pkt_reader.arp_rep_spoof(handle, mac, ip)

          macs_to_spoof[mac] = {"last_seen": now, "ip": ip}

      if((now - last_request_spoof) >= SPOOFING_TIMEOUT):
        for mac, mac_info in macs_to_spoof.items():
          pkt_reader.arp_req_spoof(handle, mac, mac_info["ip"])

        last_request_spoof = now

    pkt_reader.close_capture_dev(handle)
