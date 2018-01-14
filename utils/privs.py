#
# netwatch
# (C) 2017-18 Emanuele Faranda
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

import pwd, grp
import prctl
import os

REQUIRED_CAPABILITIES = [
  "NET_ADMIN",
  "NET_RAW",
]

def drop_privileges(uid_name, gid_name):
  # Get the uid/gid from the name
  running_uid = pwd.getpwnam(uid_name).pw_uid
  running_gid = grp.getgrnam(gid_name).gr_gid

  # Remove group privileges
  os.setgroups([])

  # Try setting the new uid/gid
  os.setgid(running_gid)
  os.setuid(running_uid)

  # Ensure a very conservative umask
  old_umask = os.umask(077)

def setup_permitted_capabilities():
  # retain permitted capabilities after uid change
  prctl.set_keepcaps(True)

  for capability in REQUIRED_CAPABILITIES:
    setattr(prctl.cap_permitted, capability.lower(), True)

def acquire_capabilities():
  for capability in REQUIRED_CAPABILITIES:
    setattr(prctl.cap_effective, capability.lower(), True)
    setattr(prctl.cap_inheritable, capability.lower(), True)
