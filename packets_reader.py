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
from utils.data import getDevicePolicy
import c_modules.pkt_reader as pkt_reader
import c_modules.nft as nft
import config

from message import Message

SNIFF_TIMEOUT = 1
SPOOFING_TIMEOUT = 0.5
SPOOFED_MAC_IDLE_TIMEOUT = 300

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
    if (not self.passive_mode) and (mac != self.gateway_mac) and \
        (mac != self.iface_mac) and (mac != "00:00:00:00:00:00") and \
        (ip != "0.0.0.0") and (not self.whitelisted_devices.get(mac)):

      policy = getDevicePolicy(mac)

      if(policy == "block") or (policy == "captive_portal") or (policy == "capture"):
        print("Policy [MAC: %s] -> %s" % (mac, policy))
        return True

    return False

  def setForwarding(self, enabled):
    if self.passive_mode:
      return

    # NOTE: packet forwarding is needed to let DNS queries pass.
    # This allows for a faster captive portal detection on client devices
    with open("/proc/sys/net/ipv4/ip_forward", 'w') as f:
      f.write('1' if enabled else '0')

  def initNftables(self):
    nft.run("add table ip nat")
    nft.run("add table ip filter")

    # Chains are marked with the "nw_" prefix to identify them
    nft.run("add chain ip nat nw_prerouting { type nat hook prerouting priority -100; }")
    nft.run("add chain ip nat nw_postrouting { type nat hook postrouting priority -100; }")
    nft.run("add chain ip filter nw_forward { type filter hook forward priority 0; }")

    nft.run("add set ip nat cp_auth_ok { type ipv4_addr;}")
    nft.run("add set ip nat cp_whitelisted { type ether_addr;}")
    nft.run("add set ip nat cp_blacklisted { type ether_addr;}")

    nft.run("add set ip filter cp_auth_ok { type ipv4_addr;}")
    nft.run("add set ip filter cp_whitelisted { type ether_addr;}")
    nft.run("add set ip filter cp_blacklisted { type ether_addr;}")

  def termNftables(self):
    # NOTE: don't delete tables as rules from other programs may be present
    nft.run("delete chain ip nat nw_prerouting")
    nft.run("delete chain ip nat nw_postrouting")
    nft.run("delete chain ip filter nw_forward")

    nft.run("delete set ip nat cp_auth_ok")
    nft.run("delete set ip nat cp_whitelisted")
    nft.run("delete set ip nat cp_blacklisted")

    nft.run("delete set ip filter cp_auth_ok")
    nft.run("delete set ip filter cp_whitelisted")
    nft.run("delete set ip filter cp_blacklisted")

  def setupCaptiveNat(self):
    # TODO
    captive_port = 9000
    self.forwarding_was_enabled = False

    # Check if forwarding is enabled to restore it after program end
    with open("/proc/sys/net/ipv4/ip_forward", 'r') as f:
      self.forwarding_was_enabled = (f.read(1) == '1')

    self.initNftables()

    # Devices are classified into 3 sets:
    #  - cp_auth_ok: devices which have passed the captive portal auth
    #  - cp_whitelisted: devices manually set as "pass" from the gui (or "capture")
    #  - cp_blacklisted: devices manually set as "block" from the gui
    # NOTE: Could use ether_addr sets with "ether saddr" match but the captive_portal
    # does not know MAC addresses
    nft.run("add rule nat nw_prerouting iif %s tcp dport { 80 } ip saddr != @cp_auth_ok ether saddr != @cp_whitelisted ether saddr != @cp_blacklisted counter dnat %s:%d" % (
      self.options["interface"], self.iface_ip, captive_port))

    # Masquerade outgoing traffic
    nft.run("add rule nat nw_postrouting oif %s counter masquerade" % (self.options["interface"], ))

    # Only allow DNS traffic to pass (otherwise captive portal detection on the device won't work)
    nft.run("add rule filter nw_forward ether saddr @cp_blacklisted counter drop")
    nft.run("add rule filter nw_forward iif %s udp dport { 53 } counter accept" % (self.options["interface"], ))
    nft.run("add rule filter nw_forward iif %s ct state new ip saddr != @cp_auth_ok ether saddr != @cp_whitelisted counter drop" % (self.options["interface"], ))

    if not self.forwarding_was_enabled:
      self.setForwarding(True)

  def reloadExceptions(self):
    if self.passive_mode:
      return

    devices = config.getConfiguredDevices()
    now = time.time()

    nft.run("flush set ip filter cp_whitelisted")
    nft.run("flush set ip filter cp_blacklisted")
    nft.run("flush set ip nat cp_whitelisted")
    nft.run("flush set ip nat cp_blacklisted")

    for mac, mac_info in devices.items():
      policy = mac_info.get("policy", "default")
      rearp_mac = False
      spoof_mac = False

      if((policy == "pass") or (policy == "capture")):
        nft.run("add element ip nat cp_whitelisted { %s }" % (mac,))
        nft.run("add element ip filter cp_whitelisted { %s }" % (mac,))

        if(policy == "pass"):
          rearp_mac = True
      elif policy == "block":
        nft.run("add element ip nat cp_blacklisted { %s }" % (mac,))
        nft.run("add element ip filter cp_blacklisted { %s }" % (mac,))
        spoof_mac = True
      elif policy == "default":
        applied_policy = getDevicePolicy(mac)

        if applied_policy == "pass":
          rearp_mac = True

      if rearp_mac:
        spoofed_mac = self.macs_to_spoof.pop(mac, None)

        if spoofed_mac:
          # The MAC was spoofed, rearp it
          pkt_reader.arp_rearp(self.handle, mac, spoofed_mac["ip"])
      elif spoof_mac and (not self.macs_to_spoof.get(mac)):
        # Try to find the MAC IP to start blocking it
        found_ip = None

        for ip, m in self.ip_to_mac.items():
          if m == mac:
            found_ip = ip
            break

        if found_ip:
          self.macs_to_spoof[mac] = {"last_seen": now, "ip": found_ip}

  def termCaptiveNat(self):
    self.termNftables()

    if not self.forwarding_was_enabled:
      self.setForwarding(False)

  def task(self, msg_queue, cp_eventsqueue, config_changeev, passive_mode):
    self.msg_queue = msg_queue
    self.cp_eventsqueue = cp_eventsqueue
    self.passive_mode = passive_mode
    self.config_changeev = config_changeev
    self.macs_to_spoof = {}
    self.ip_to_mac = {}

    # Acquire capabilities to capture packets
    acquire_capabilities()

    # TODO make interface configurable
    handle = pkt_reader.open_capture_dev(self.options["interface"], 1000, "broadcast or arp", False)
    self.gateway_mac = pkt_reader.get_gateway_mac(handle)
    self.iface_ip = pkt_reader.get_iface_ip(handle)
    self.iface_mac = pkt_reader.get_iface_mac(handle)
    self.handle = handle

    if(not self.passive_mode):
      print("[IP: %s] [MAC: %s] Gateway %s (%s)" % (self.iface_ip, self.iface_mac, self.gateway_mac, pkt_reader.get_gateway_ip(handle)))

      self.setupCaptiveNat()
      self.reloadExceptions()

    last_request_spoof = 0

    while self.isRunning():
      info = pkt_reader.read_packet_info(handle)
      now = time.time()

      # Check for captive portal events
      while cp_eventsqueue[1].poll():
        (msg_type, ip) = cp_eventsqueue[1].recv()

        if(msg_type == "auth_ok"):
          # A device was successfully authenticated
          mac = self.ip_to_mac.get(ip)

          if not mac:
            print("Warning: unknown device with IP: " + ip)
          else:
            # Verify that the device has actually a captive_portal logic
            policy = getDevicePolicy(mac)

            if policy == "captive_portal":
              print("Whitelisting device [MAC=%s][IP=%s]" % (mac, ip))
              self.whitelisted_devices[mac] = True

              # Spoof the device back to the original gateway
              pkt_reader.arp_rearp(handle, mac, ip)
              self.macs_to_spoof.pop(mac, None)

      # Check for config change events
      if self.config_changeev.is_set():
        config.reload()
        self.reloadExceptions()
        self.config_changeev.clear()

      if info:
        name = info.get("name")
        mac = info["mac"]
        ip = info["ip"]

        self.handleHost(mac, ip, name, now)

        #print(info)

        if self.shouldSpoof(mac, ip):
          if(info.get("proto") == "ARP_REQ"):
            # Immediately spoof the reply
            pkt_reader.arp_rep_spoof(handle, mac, ip)

          self.macs_to_spoof[mac] = {"last_seen": now, "ip": ip}

        self.ip_to_mac[ip] = mac

      if((now - last_request_spoof) >= SPOOFING_TIMEOUT):
        idle_macs = []

        for mac, mac_info in self.macs_to_spoof.items():
          if((now - mac_info["last_seen"]) < SPOOFED_MAC_IDLE_TIMEOUT):
            pkt_reader.arp_req_spoof(handle, mac, mac_info["ip"])
          else:
            idle_macs.append(mac)

        for mac in idle_macs:
          self.macs_to_spoof.pop(mac, None)

        last_request_spoof = now

    # Spoof the devices back to the original gateway
    for mac, mac_info in self.macs_to_spoof.items():
      pkt_reader.arp_rearp(handle, mac, mac_info["ip"])

    if not self.passive_mode:
      self.termCaptiveNat()

    pkt_reader.close_capture_dev(handle)
