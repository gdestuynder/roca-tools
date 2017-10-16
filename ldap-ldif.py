#!/usr/bin/env python
from ldif3 import LDIFParser
from pprint import pprint
import detect

# This script uses 'keys.ldif' as input LDIF file AND expect `sshPublicKey` as attribute for SSH public keys

parser = LDIFParser(open('keys.ldif', 'rb'))
vuln = 0
for dn, entry in parser.parse():
    if not entry.has_key('sshPublicKey'):
        continue
    for i in entry['sshPublicKey']:
        if detect.detect(dn, i):
            vuln = vuln+1
print('SUMMARY', 'Found {} vulnerable keys'.format(vuln))
