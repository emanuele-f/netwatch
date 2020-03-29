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

from datetime import datetime, timedelta
import calendar
import time

def dateToTimestamp(dt):
  return time.mktime(dt.timetuple())

def makeEndTimestamp(ts_start, res):
  dt = datetime.fromtimestamp(ts_start)

  if res == "1m":
    dt = dt + timedelta(hours=1)
  elif res == "15m":
    dt = dt + timedelta(hours=1)
  elif res == "1h":
    dt = dt + timedelta(days=1)
  elif res == "24h":
    dt = dt + timedelta(weeks=4)
  elif res == "1M":
    dt = dt + timedelta(days=365)
  else:
    print("[ERROR] Unknown resolution: ", res)

  return dateToTimestamp(dt)
