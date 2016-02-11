import os
import resource
import time
import random
import threading
import string
from locust import HttpLocust, TaskSet, task

resource.setrlimit(resource.RLIMIT_NOFILE, (999999, 999999))

letters = string.ascii_letters + string.digits
pid = os.getpid()
tid = threading.current_thread().ident
counter = 0
payloads = [l.strip() for l in open('/home/ubuntu/sample', 'r').readlines()]
maxind = len(payloads) - 1


def rand_payload():
    return payloads[random.randint(0, maxind)]


class UserBehavior(TaskSet):
    @task
    def fire_track(self):
        global counter
        counter += 1
        self.client.post("/NODE_NAME/{}/{}/{}{}/".format(pid, time.time(), counter, rand_payload()), name="/NODE_NAME/{}/{}".format(pid, tid))


class WebsiteUser(HttpLocust):
    host = 'http://logserver.analytics-tracker.thescore.com'
    task_set = UserBehavior
    min_wait = 500
    max_wait = 8000
