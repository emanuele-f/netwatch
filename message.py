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

class Message:
  def __init__(self, mac, ip, seen_tstamp):
    self.mac = mac
    self.ip = ip
    self.seen_tstamp = seen_tstamp
    self.host_name = None
    self._next = True

  def __iter__(self):
    return self

  def next(self):
    if self._next:
      self._next = False
      return self
    else:
      raise StopIteration()

class Messages:
  def __init__(self, messages):
    self.messages = messages

  def __iter__(self):
    return iter(self.messages)
