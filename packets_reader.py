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
import c_modules.nft as nft

from message import Message

SNIFF_TIMEOUT = 1
MAC_IDLE_TIMEOUT = 15

# TODO
SPOOFING_ENABLED = False
SPOOFING_DEFAULT_SPOOF = False
SPOOFING_TIMEOUT = 0.5
SPOOFING_EXCEPTIONS = {}

class PacketsReaderJob(Job):
  def __init__(self):
    super(PacketsReaderJob, self).__init__("PacketsReaderJob", self.task)
    self.cp_eventsqueue = None
    self.whitelisted_devices = {}

  def handleHost(self, host_mac, host_ip, host_name, now):
    if host_mac != "00:00:00:00:00:00":
      # TODO handle queue full
      msg = Message(host_mac, host_ip, now)
      if host_name:
        msg.host_name = host_name
      self.msg_queue.put(msg)

  def shouldSpoof(self, mac, ip):
    if SPOOFING_ENABLED and (mac != self.gateway_mac) and \
        (mac != self.iface_mac) and (mac != "00:00:00:00:00:00") and \
        (ip != "0.0.0.0") and (not self.whitelisted_devices.get(mac)):
      is_exception = SPOOFING_EXCEPTIONS.get(mac)

      if((SPOOFING_DEFAULT_SPOOF and not is_exception) or
          (not SPOOFING_DEFAULT_SPOOF and is_exception)):
        return True

    return False

  def setForwarding(self, enabled):
    # NOTE: packet forwarding is needed to let DNS queries pass.
    # This allows for a faster captive portal detection on client devices
    with open("/proc/sys/net/ipv4/ip_forward", 'w') as f:
      f.write('1' if enabled else '0')

  def setupCaptiveNat(self):
    # TODO
    captive_port = 9000
    self.forwarding_was_enabled = False

    # Check if forwarding is enabled to restore it after program end
    with open("/proc/sys/net/ipv4/ip_forward", 'r') as f:
      self.forwarding_was_enabled = (f.read(1) == '1')

    nft.run("add table ip nat")
    # NOTE: Could use ether_addr sets with "ether saddr" match but the captive_portal
    # does not know MAC addresses
    nft.run("add set ip nat cp_whitelisted { type ipv4_addr;}")
    nft.run("add chain nat prerouting { type nat hook prerouting priority -100; }")
    nft.run("add rule nat prerouting iif %s tcp dport { 80 } ip saddr != @cp_whitelisted counter dnat %s:%d" % (
      self.options["interface"], self.iface_ip, captive_port))

    # Masquerade outgoing traffic
    nft.run("add chain nat postrouting { type nat hook postrouting priority -100; }")
    nft.run("add rule nat postrouting oif %s counter masquerade" % (self.options["interface"], ))

    # Only allow DNS traffic to pass (otherwise captive portal detection on the device won't work)
    nft.run("add table ip filter")
    nft.run("add set ip filter cp_whitelisted { type ipv4_addr;}")
    nft.run("add chain filter forward { type filter hook forward priority 0; }")
    nft.run("add rule filter forward iif %s udp dport { 53 } counter accept" % (self.options["interface"], ))
    nft.run("add rule filter forward ip saddr != @cp_whitelisted ct state new counter drop")

    if not self.forwarding_was_enabled:
      self.setForwarding(True)

  def termCaptiveNat(self):
    nft.run("delete table ip nat")
    nft.run("delete table ip filter")

    if not self.forwarding_was_enabled:
      self.setForwarding(False)

  def task(self, msg_queue, cp_eventsqueue):
    self.msg_queue = msg_queue
    self.cp_eventsqueue = cp_eventsqueue

    # Acquire capabilities to capture packets
    acquire_capabilities()

    # TODO make interface configurable
    handle = pkt_reader.open_capture_dev(self.options["interface"], 1000, "broadcast or arp", False)
    self.gateway_mac = pkt_reader.get_gateway_mac(handle)
    self.iface_ip = pkt_reader.get_iface_ip(handle)
    self.iface_mac = pkt_reader.get_iface_mac(handle)
    self.handle = handle

    if SPOOFING_ENABLED:
      print("[IP: %s] [MAC: %s] Gateway %s (%s)" % (self.iface_ip, self.iface_mac, self.gateway_mac, pkt_reader.get_gateway_ip(handle)))

    self.setupCaptiveNat()

    macs_to_spoof = {}
    ip_to_mac = {}
    last_request_spoof = 0

    while self.isRunning():
      info = pkt_reader.read_packet_info(handle)
      now = time.time()

      while cp_eventsqueue[1].poll():
        (msg_type, ip) = cp_eventsqueue[1].recv()

        if(msg_type == "auth_ok"):
          # A device was successfully authenticated
          mac = ip_to_mac.get(ip)

          if not mac:
            print("Warning: unknown device with IP: " + ip)
          else:
            print("Whitelisting device [MAC=%s][IP=%s]" % (mac, ip))
            self.whitelisted_devices[mac] = True

            # Spoof the device back to the original gateway
            pkt_reader.arp_rearp(handle, mac, ip)
            macs_to_spoof.pop(mac, None)

      if info:
        name = info.get("name")
        mac = info["mac"]
        ip = info["ip"]

        self.handleHost(mac, ip, name, now)

        if self.shouldSpoof(mac, ip):
          if(info.get("proto") == "ARP_REQ"):
            # Immediately spoof the reply
            pkt_reader.arp_rep_spoof(handle, mac, ip)

          macs_to_spoof[mac] = {"last_seen": now, "ip": ip}
          ip_to_mac[ip] = mac

      if((now - last_request_spoof) >= SPOOFING_TIMEOUT):
        idle_macs = []

        for mac, mac_info in macs_to_spoof.items():
          if((now - mac_info["last_seen"]) < MAC_IDLE_TIMEOUT):
            pkt_reader.arp_req_spoof(handle, mac, mac_info["ip"])
          else:
            idle_macs.append(mac)

        for mac in idle_macs:
          macs_to_spoof.pop(mac, None)

        last_request_spoof = now

    # Spoof the devices back to the original gateway
    for mac, mac_info in macs_to_spoof.items():
      pkt_reader.arp_rearp(handle, mac, mac_info["ip"])

    self.termCaptiveNat()

    pkt_reader.close_capture_dev(handle)
