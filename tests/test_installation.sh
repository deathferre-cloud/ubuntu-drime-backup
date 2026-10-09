#!/usr/bin/env bash
# This test installs into /opt and /etc. ONLY for a fresh disposable CI runner.
set -euo pipefail
[ "${UBUNTU_DRIME_TEST_DISPOSABLE:-}" = 1 ] && [ "$(id -u)" = 0 ] || {
  echo 'Disposable root runner required. Do not run on a real server.' >&2; exit 1;
}
for path in /opt/ubuntu-drime-backup /etc/ubuntu-drime-backup /var/lib/ubuntu-drime-backup; do
  [ ! -e "$path" ] || { echo 'Fresh installation required.' >&2; exit 1; }
done
project=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project"
bash scripts/install.sh --rclone "$project/dist/rclone-fast"
python3 - <<'PY'
import getpass,json,os,pathlib,runpy,subprocess,tempfile
from unittest.mock import patch
root=pathlib.Path('/etc/ubuntu-drime-backup')
with tempfile.TemporaryDirectory(prefix='ubuntu-drime-install-fixture-') as source:
    answers=iter(['12345','fixture@example.com',source])
    with patch('builtins.input',side_effect=lambda _:next(answers)),patch('getpass.getpass',return_value='FAKE-TEST-TOKEN'):
        runpy.run_path('scripts/configure.py',run_name='__main__')
    cfg=json.loads((root/'backup.json').read_text())
    assert cfg['include_roots']==[source] and cfg['required_roots']==[source]
    assert cfg['cloud_guard_workspace']==12345
    for name in ('backup.json','rclone.conf'):
        assert (root/name).stat().st_mode & 0o777 == 0o600
    assert subprocess.run(['systemctl','is-active','--quiet','ubuntu-drime-backup']).returncode != 0
    assert not pathlib.Path('/var/lib/ubuntu-drime-backup/journal.sqlite3').exists()
    again=subprocess.run(['python3','scripts/configure.py'],capture_output=True,text=True)
    assert again.returncode != 0 and 'already exists' in again.stderr
print('Fresh configuration is private, refuses overwrite and does not start backup.')
PY
python3 scripts/configure-panel.py --public-url https://backup.example.com/backup-control.php
systemctl start ubuntu-drime-backup-control
trap 'systemctl stop ubuntu-drime-backup-control' EXIT
python3 - <<'PY'
import hashlib,json,pathlib,socket,time,urllib.parse
state=pathlib.Path('/var/lib/ubuntu-drime-backup')
auth=json.loads(pathlib.Path('/etc/ubuntu-drime-backup/control-auth.json').read_text())
key=urllib.parse.parse_qs(urllib.parse.urlsplit((state/'control-url.txt').read_text().strip()).query)['key'][0]
assert hashlib.sha256(key.encode()).hexdigest()==auth['key_sha256']
path='/run/ubuntu-drime-backup-control/control.sock'
for _ in range(100):
    if pathlib.Path(path).exists():break
    time.sleep(.1)
def request(key):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(10);conn.connect(path)
        conn.sendall(json.dumps(dict(key=key,action='status')).encode()+b'\n')
        with conn.makefile('rb') as f:return json.loads(f.readline())
assert request('0'*64)['ok'] is False
response=request(key)
assert response['ok'] is True,response.get('error')
assert response['status']['service']['ActiveState']!='active'
assert (state/'control-url.txt').stat().st_mode & 0o777 == 0o600
print('Authenticated control socket passed; no backup started or Drime requests made.')
PY
