#!/usr/bin/env python3
"""Interactive configuration; credentials are never command-line arguments."""
import configparser
import getpass
import io
import json
import os
import pathlib
import subprocess
import sys


def write_secret(path,data):
    tmp=path.with_name(path.name+'.new')
    with tmp.open('w',encoding='utf8') as f:
        os.chmod(tmp,0o600);f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)


def main():
    if os.geteuid()!=0:raise SystemExit('Run with sudo.')
    root=pathlib.Path('/etc/ubuntu-drime-backup')
    if not (root/'backup.example.json').exists():raise SystemExit('Run scripts/install.sh first.')
    if subprocess.run(['systemctl','is-active','--quiet','ubuntu-drime-backup']).returncode==0:
        raise SystemExit('Stop ubuntu-drime-backup before reconfiguring it.')
    if (root/'backup.json').exists() or (root/'rclone.conf').exists():
        raise SystemExit('Configuration already exists. Edit it in place; this helper does not replace credentials.')
    workspace=int(input('Drime workspace ID (dedicated backup workspace): ').strip())
    if workspace<=0:raise ValueError('Workspace ID must be positive')
    actor=input('Account email used by the backup: ').strip()
    if '@' not in actor or any(c.isspace() for c in actor):raise ValueError('Enter the account email')
    token=getpass.getpass('Drime API access token (hidden): ').strip()
    if not token or any(c.isspace() for c in token):raise ValueError('Invalid API token')
    cfg=json.loads((root/'backup.example.json').read_text())
    defaults=[p for p in cfg['include_roots'] if pathlib.Path(p).is_dir()]
    raw=input('Absolute folders, comma separated ['+', '.join(defaults)+']: ').strip()
    paths=[p.strip() for p in raw.split(',')] if raw else defaults
    state=pathlib.Path('/var/lib/ubuntu-drime-backup')
    for p in paths:
        folder=pathlib.Path(p)
        if not folder.is_absolute() or not folder.is_dir() or folder.is_symlink():raise ValueError('Not a real absolute folder: '+p)
        if folder==state or folder in state.parents:raise ValueError('Do not include the backup journal itself: '+p)
    cfg.update(include_roots=paths,required_roots=paths,cloud_guard_workspace=workspace,cloud_guard_actor_email=actor)
    remote=configparser.ConfigParser(interpolation=None)
    remote['drime']={'type':'drime','workspace_id':str(workspace),'access_token':token,
        'upload_cutoff':'8Ki','list_chunk':'100','chunk_size':'64Mi','upload_concurrency':'1','fast_list_upload':'true'}
    stream=io.StringIO();remote.write(stream)
    write_secret(root/'rclone.conf',stream.getvalue())
    write_secret(root/'backup.json',json.dumps(cfg,indent=2)+'\n')
    print('Saved root-only configuration. Review Drime alert policies and run the preflight in README.md before starting.')


if __name__=='__main__':main()
