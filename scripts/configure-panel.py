#!/usr/bin/env python3
"""Create the optional web panel key. Does not configure nginx or start services."""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import urllib.parse
from configure import write_secret

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--public-url',required=True,help='https://backup.example.com/backup-control.php')
args=p.parse_args();url=urllib.parse.urlsplit(args.public_url)
if os.geteuid()!=0:raise SystemExit('Run with sudo.')
if url.scheme!='https' or not url.hostname or url.path!='/backup-control.php' or url.query or url.fragment or url.username:
    raise SystemExit('Use an HTTPS URL ending exactly in /backup-control.php, without query or credentials.')
auth=pathlib.Path('/etc/ubuntu-drime-backup/control-auth.json')
state=pathlib.Path('/var/lib/ubuntu-drime-backup')
if auth.exists():raise SystemExit('A key already exists. Read control-url.txt; this helper does not silently rotate it.')
if not auth.parent.is_dir() or not state.is_dir():raise SystemExit('Run install.sh first.')
key=secrets.token_hex(32)
write_secret(auth,json.dumps({'key_sha256':hashlib.sha256(key.encode()).hexdigest()})+'\n')
write_secret(state/'control-url.txt',args.public_url+'?key='+key+'\n')
print('Key created. Personal URL is in /var/lib/ubuntu-drime-backup/control-url.txt (root only).')
