
from datetime import datetime, timedelta

def dateToTimestamp(dt):
  epoch = datetime(1970, 1, 1)
  diff = dt - epoch
  return int(diff.total_seconds())

def makeEndTimestamp(ts_start, res):
  dt = datetime.fromtimestamp(ts_start)

  if res == "1m":
    dt = dt + timedelta(minutes=20)
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
