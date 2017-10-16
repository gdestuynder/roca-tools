#!/usr/bin/env python2

import requests
import github3
import detect
import os, sys
import time

github_org = "mozilla"
# Get em tokens here: https://github.com/settings/tokens
# you need scope read:org as well
token = ''


g = github3.login(token=token)
org = g.organization(github_org)
vuln = 0
if not org:
    print('ERROR', 'no org found')
    sys.exit(1)
for u in org.members(role='all'):
    keys = u.keys()
    for k in keys:
        if detect.detect(u.login, k.key):
            vuln = vuln +1
print('INFO', 'Found {} vulnerable keys'.format(vuln))
