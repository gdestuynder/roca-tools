#!/usr/bin/env python
from ldif3 import LDIFParser
from pprint import pprint
import os, sys, subprocess

def detect(dn, sshkey):
    if len(sshkey) < 10 or not sshkey.startswith('ssh'):
        print('SKIP', dn, sshkey, "is of incorrect format, skipping")
        return False
    elif sshkey.startswith("ssh-dss"):
        print('SKIP', dn, sshkey, "Key is DSA skipping")
        return False
    elif sshkey.startswith("ssh-ed25519"):
        print('SKIP', dn, sshkey, "Key is ED25519 skipping")
        return False
    elif sshkey[2] == ':':
        print('SKIP', dn, sshkey, "is a fingerprint, not a public key, skipping")
        return False
    with open('/tmp/key.pub', 'w+') as fd:
        fd.write(sshkey+'\n')
        fd.close()
        out = subprocess.check_output('roca-detect --dump --flatten --indent --file-ssh /tmp/key.pub',
                                      stderr=subprocess.STDOUT, shell=True)
        if out.find('ERROR') != -1:
            print("FATAL: UNHANDLED ERROR", out)
            sys.exit(1)

        if out.find('No fingerprinted keys found (OK)') != -1:
            print('OK', dn, sshkey)
            return False
        else:
            print('VULNERABLE', dn, sshkey)
            print(out)
            return True

parser = LDIFParser(open('keys.ldif', 'rb'))
vuln = 0
for dn, entry in parser.parse():
    if not entry.has_key('sshPublicKey'):
        continue
    for i in entry['sshPublicKey']:
        if detect(dn, i):
            vuln = vuln+1
print('SUMMARY', 'Found {} vulnerable keys'.format(vuln))
