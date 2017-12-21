#!/bin/env python2

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
