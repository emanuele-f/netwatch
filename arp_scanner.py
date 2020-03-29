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
import subprocess
from queue import Empty as QueueEmpty

from utils.jobs import Job
from utils.privs import acquire_capabilities
import c_modules.arp_scanner as arp_scanner

NUM_SCAN_REPEATS = 2

def getDeviceNetwork(device):
  output = subprocess.check_output(['ip', '-4', '-o', 'addr', 'show', 'dev', device])

  if output:
    parts = output.split()
    if len(parts) >= 4:
      return parts[3]

  # fallback
  return "192.168.1.1/24"

class ARPScannerJob(Job):
  def __init__(self):
    super(ARPScannerJob, self).__init__("ARPScannerJob", self.task)

  def task(self, _, tasks_queue):
    # Acquire capabilities to send packets
    acquire_capabilities()

    handle = arp_scanner.init_scanner(self.options["interface"])
    net_range = getDeviceNetwork(self.options["interface"])

    while self.isRunning():
      task = None

      try:
        task = tasks_queue.get(True, 2)
      except QueueEmpty:
        pass

      if task:
        if task == "net_scan":
          print("ARP scanning network " + net_range)

          for i in xrange(NUM_SCAN_REPEATS):
            arp_scanner.scan_network(handle, net_range)
        else:
          print("Scanning host " + task)

          for i in xrange(NUM_SCAN_REPEATS):
            arp_scanner.scan_ip(handle, task)

    arp_scanner.finish_scanner(handle)
