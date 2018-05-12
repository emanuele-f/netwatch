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

# NOTE: use multiprocessing instead of threading to make things go smooth
# The Global Interpreter Lock slows down web server a lot!
from multiprocessing import Queue, Event, Process
from Queue import Empty as QueueEmpty
import signal
import os

class Job(object):
  def __init__(self, idenfier, task):
    self.id = idenfier
    self.task = task
    self._stopped = Event()
    self.options = {}

  def askTerminate(self):
    self._stopped.set()

  def waitTermination(self):
    self._stopped.wait()

  def isTerminating(self):
    return self._stopped.is_set()

  def isRunning(self):
    return not self.isTerminating()

  def readOptions(self, options):
    self.options = options

class ManagedJob(object):
  def __init__(self, job, thread):
    self.job = job
    self.thread = thread

# Manages jobs. Jobs with the same identifier can only run one at a time.
class JobsManager:
  def __init__(self, global_options):
    self.running = {}
    self.msg_queue = Queue()
    self.global_options = global_options

  def _execJob(self, job, *args):
    #print("Job[%d]: %s" % (os.getpid(), job.id))
    job.task(*args)

  def _checkJoin(self, wait=False):
    jobs_removed = []

    for job_id, job in self.running.iteritems():
      if wait or (not job.thread.is_alive()):
        job.thread.join()
        jobs_removed.append(job_id)

    for job_id in jobs_removed:
      del self.running[job_id]

  def getMessages(self):
    messages = []

    try:
      while True:
        msg = self.msg_queue.get(block=False)
        messages.append(msg)
    except QueueEmpty:
      pass

    return messages

  def runJob(self, job, args=()):
    self._checkJoin()

    if job.id in self.running:
      return False

    # Disable signals on the child process
    old_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    old_sigterm_handler = signal.signal(signal.SIGTERM, signal.SIG_IGN)
    old_sighup_handler = signal.signal(signal.SIGHUP, signal.SIG_IGN)

    args = (job, self.msg_queue, ) + args
    job.readOptions(self.global_options)
    self.running[job.id] = ManagedJob(job, Process(target=self._execJob, args=args))
    self.running[job.id].thread.start()

    # Re-enable signals on the main process
    signal.signal(signal.SIGINT, old_sigint_handler)
    signal.signal(signal.SIGTERM, old_sigterm_handler)
    signal.signal(signal.SIGHUP, old_sighup_handler)
    return True

  def newQueue(self):
    return Queue()

  def getRunning(self):
    self._checkJoin()
    return [job.job for job_id, job in self.running.iteritems() if job.thread.is_alive()]

  def terminate(self):
    self._checkJoin()

    for job_id, job in self.running.iteritems():
      if job.thread.is_alive():
        job.job.askTerminate()

  def kill(self):
    self._checkJoin()

    for job_id, job in self.running.iteritems():
      if job.thread.is_alive():
        job.thread.terminate()

  def join(self, wait=False):
    self._checkJoin(wait)

if __name__ == "__main__":
  import time

  def sleeper_task(msg_queue, seconds):
    time.sleep(seconds)
    msg_queue.put(seconds)

  manager = JobsManager()
  manager.runJob(Job("sleep_2", sleeper_task), (2, ))
  manager.runJob(Job("sleep_5", sleeper_task), (5, ))
  manager.runJob(Job("sleep_2", sleeper_task), (2, ))

  assert(len(manager.getRunning()) == 2)

  manager.terminate()
  time.sleep(3)
  manager.join()

  still_running = manager.getRunning()
  assert(len(still_running) == 1)
  assert(still_running[0].id == "sleep_5")

  manager.join(wait=True)
  assert(len(manager.getRunning()) == 0)

  messages = manager.getMessages()
  assert(2 in messages)
  assert(5 in messages)
