#!/usr/bin/env python

import os
import socket
from salt.utils import event as salt_event

SALT_EVENT_RESPONSE_TAG='request/certificate'
SALT_SOCKET_DIR = '/var/run/salt'
SALT_EVENT_TRANSPORT = 'zeromq'


def _job_contains_cert_data(data):
    """Boolean checks to ensure any received job message contains return cert data"""
    if data is None:
        return False

    if 'cert' in data['data']:
        return True
    else:
        return False

opts = {}
opts['func_count'] = ''
opts['id'] = socket.getfqdn()
opts['node'] = 'minion'
opts['transport'] = SALT_EVENT_TRANSPORT
opts['sock_dir'] = os.path.join(SALT_SOCKET_DIR, opts['node'])
event = salt_event.get_event(
    opts['node'],
    sock_dir=opts['sock_dir'],
    transport=opts['transport'],
    opts=opts,
    listen=True)

job_counter = 0
while True:
    print("Attempt number: {}".format(job_counter))
    ret = event.get_event(full=True)

    print("{}".format(ret))

    if ret is None:
        print('[_minion_event] No event data in packet')
        job_counter += 1
        continue
    data = ret.get('data', False)
    if data and ret['tag'] == SALT_EVENT_RESPONSE_TAG:
        if _job_contains_cert_data(data):
            print('[_minion_event] Job contains cert data!')
            print(data)
            exit(0)
        else:
            print('[_minion_event] Job does not contains cert data. :(')
            job_counter += 1
            continue
