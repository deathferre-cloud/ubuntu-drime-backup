#!/usr/bin/env python3
"""Authenticated Unix-socket bridge; only controls this one backup unit."""
import fcntl
import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import os
import pathlib
import re
import socketserver
import sqlite3
import subprocess
import sys
import time
from zoneinfo import ZoneInfo
from safety import SafetyGuard, atomic_json, now, sanitize
import progress

CONFIG = pathlib.Path('/etc/ubuntu-drime-backup/backup.json')
AUTH = pathlib.Path('/etc/ubuntu-drime-backup/control-auth.json')
SOCKET = '/run/ubuntu-drime-backup-control/control.sock'
UNIT = 'ubuntu-drime-backup.service'
ROOT = pathlib.Path('/var/lib/ubuntu-drime-backup')
# Python writes its level in MESSAGE; journald otherwise labels stdout as INFO.
ERROR_PATTERN = (r'^(?:\d{4}-\d{2}-\d{2} [\d:]+(?:[,.]\d+)? )?'
                 r'(?:(?:ERROR|CRITICAL|FATAL)(?:\s|:)|'
                 r'WARNING (?:rclone (?:error|fatal)\b|(?:DAY|NIGHT) error:))'
                 r'|^(?:DAY|NIGHT) error:')


def systemctl(*args):
    return subprocess.run(['/usr/bin/systemctl', *args, UNIT], capture_output=True, text=True, timeout=55)


def read_json(path):
    try: return json.loads(path.read_text())
    except (OSError, ValueError): return {}


def stop_backup():
    atomic_json(ROOT/'MANUAL_STOP.json',dict(at=now(),reason='Operator requested a persistent manual stop'))
    result=systemctl('stop')
    if result.returncode: raise RuntimeError('Service stop failed; manual latch remains set')


def explain_error(message):
    """Plain-language guidance from explicit evidence in the log, never a guessed cause."""
    text=message.lower()
    if 'folder with same name already exists' in text:
        return ('Drime сообщил, что папка с таким именем уже существует, и отклонил её создание. '
                'Это конфликт создания папки, а не доказательство потери файлов. Обработка этого случая уже добавлена в клиент. '
                'Если запись новая и повторяется после обновления, нужно проверить точный путь и возможные одноимённые папки; удалять их наугад не следует.')
    if any(word in text for word in ('sha256','sha-256')) and any(word in text for word in ('mismatch','не совп')):
        return ('Скачанный контрольный файл не совпал с исходным по контрольной сумме. Служба не считает такую копию исправной и возвращает файл в очередь. '
                'Нужно проверить конкретный исходник и его облачную версию; до проверки не полагайтесь на эту копию.')
    if 'error limit reached' in text or 'error budget exhausted' in text:
        return ('Набралось 5 дневных ошибок с последнего ручного сброса. Сработала защита и остановила копирование. '
                'Сначала разберите предыдущие ошибки в таблице и устраните причину, затем нажмите «Снять блокировку и запустить».')
    if any(word in text for word in ('no observable progress','stall deadline','maximum command duration')):
        return ('Копирование слишком долго не показывало продвижения либо команда превысила допустимую длительность. '
                'Служба прервала её, чтобы не оставлять зависший процесс. Днём это блокирует службу, ночью будет повтор. '
                'Нужно проверить доступность Drime, сеть и размер проблемной партии.')
    if any(word in text for word in ('did not exit cleanly','unclean prior run','unclean_night_restart')):
        return ('Предыдущий процесс завершился без штатного закрытия. Это могло произойти при выключении сервера или аварийном завершении программы; '
                'эта строка не устанавливает точную причину. Подтверждённая очередь сохранена. Проверьте состояние сервера и журнал перед ручным запуском.')
    if 'expected alert policy changed' in text or 'mail-storm prevention policy changed' in text:
        return ('Настройки оповещений Drime отличаются от ожидаемых: правила и письма должны быть включены, а обычные программные расширения исключены из условий оповещения. '
                'Проверьте эти настройки в Ubuntu Drime Backup. Днём такое расхождение останавливает службу; исправление требует проверки настроек, а не удаления файлов.')
    if 'cloud activity exceeded' in text or 'cloud_observation_gap' in text:
        return ('Между проверками в Drime появилось больше событий, чем помещается на одной странице журнала. Служба не может гарантировать, '
                'что увидела все предупреждения. Днём она останавливается, ночью продолжает с записью о пропуске. Нужно проверить журнал Drime и частоту опроса.')
    if 'cloud_alert' in text or 'alert_malware_' in text or 'alert_ransomware_' in text:
        return ('В Drime сработало правило безопасности. По одной этой записи нельзя утверждать, что сервер заражён: правило может реагировать на расширения файлов. '
                'Откройте журнал активности Ubuntu Drime Backup, проверьте имя файла и условие правила. Подозрительный файл требует отдельной проверки.')
    if any(word in text for word in ('no space left on device','disk quota exceeded')):
        return ('Операция не смогла записать данные: закончилось доступное место либо превышена квота на указанном в ошибке хранилище. '
                'Проверьте свободное место и inode на сервере, а также квоту Drime. Не удаляйте журнал очереди или резервные копии без разбора.')
    if any(word in text for word in ('storage quota','insufficient storage')) or re.search(r'\bhttp\s+507\b',text):
        return ('Хранилище отказало в записи из-за нехватки доступного места или квоты. Проверьте объём пространства Drime, включая историю версий и корзину; '
                'после решения проблемы можно повторить отправку.')
    if re.search(r'\b(?:http(?:/[\d.]+)?\s+401|401\s+unauthorized)\b',text):
        return ('Drime не принял данные авторизации. Возможно, токен истёк или был отозван; это нужно проверить. '
                'Потребуется восстановить доступ клиента к аккаунту. Не публикуйте токен или пароль в журнале и переписке.')
    if re.search(r'\b(?:http(?:/[\d.]+)?\s+403|403\s+forbidden)\b',text):
        return ('Сервер запретил запрос. Причиной могут быть права в пространстве Drime или ограничения доступа; сама строка не доказывает проблему с паролем. '
                'Проверьте нужный аккаунт, пространство Ubuntu Drime Backup и разрешения на запись.')
    if re.search(r'\b(?:http(?:/[\d.]+)?\s+429|429\s+too many requests)\b',text) or 'too many requests' in text:
        return ('Drime ограничил частоту запросов: клиент обращался слишком часто. Нужно дать сервису время и при повторении уменьшить число потоков или запросов в секунду. '
                'Постоянные ручные перезапуски могут усилить ограничение.')
    if re.search(r'\b(?:http(?:/[\d.]+)?\s+5\d\d|5\d\d\s+(?:internal server error|bad gateway|service unavailable|gateway timeout))\b',text):
        return ('Удалённый сервер вернул внутреннюю ошибку или оказался временно недоступен. Причина находится на стороне обработчика запроса или промежуточного сервера. '
                'Повтор может помочь; при длительном повторении проверьте работу Drime. Эта строка сама по себе не означает повреждение исходных файлов.')
    if any(word in text for word in ('no such host','temporary failure in name resolution','server misbehaving','could not resolve host')):
        return ('Не удалось определить сетевой адрес сервиса по его имени — ошибка DNS. Пока адрес не получен, загрузка невозможна. '
                'Нужно проверить доступность DNS и сети из среды резервного копирования; рабочую настройку DNS всего сервера менять наугад не следует.')
    if any(word in text for word in ('i/o timeout','timeout awaiting response headers','context deadline exceeded','timed out','connection timeout')):
        if "couldn't list files" in text or '/drive/file-entries' in text:
            return ('Сеть или Drime не ответили вовремя при чтении списка файлов или папок. Это не означает, что уже отправленные файлы потеряны. '
                    'Подтверждённые отправки сохранены; следующая команда заново читает нужные каталоги. После исчерпания сетевых повторов ошибка учитывается дневной защитой.')
        return ('Сеть или Drime не ответили за отведённое время. При загрузке результат может быть неопределённым: облако могло принять файл, но ответ не дошёл. '
                'Неподтверждённый путь остаётся в очереди; после задержки повтора он имеет приоритет. Перед повторной загрузкой клиент проверяет существующий объект. '
                'По одной строке нельзя отличить сбой маршрута от медленного ответа облака.')
    if any(word in text for word in ('network is unreachable','connection refused','connection reset','broken pipe')):
        return ('Не удалось установить или удержать сетевое соединение. Причина может быть в маршруте, ограничении сети или отказе удалённого сервиса. '
                'Файл остаётся для повтора; при повторении нужно проверить соединение с адресом, указанным в ошибке.')
    if 'permission denied' in text:
        return ('Операции не хватило прав на указанный файл, каталог или ресурс. Проверьте путь и пользователя процесса. '
                'Не исправляйте это массовой выдачей прав 777: нужно восстановить именно требуемый доступ.')
    if 'required source path is missing' in text or 'no such file or directory' in text:
        return ('Нужный файл или каталог не найден. Он мог быть перемещён, удалён или стать недоступным вместе с диском. '
                'Проверьте точный путь в сообщении; если это обязательный каталог копирования, восстановите его доступность.')
    if any(word in text for word in ('process crashed','service terminated','main process exited','failed with result')):
        return ('Процесс завершился аварийно либо с ошибкой. Эта запись фиксирует остановку, но не всегда объясняет её причину. '
                'Смотрите предыдущие ошибки и системный журнал; ночью предусмотрен перезапуск, днём сохраняется аварийная блокировка.')
    if '0 unconfirmed files retained' in text or 'all batch files were individually confirmed' in text:
        return ('Команда завершилась с ошибкой, но все файлы этой пачки уже получили отдельные подтверждения успешной отправки. '
                'Повторная загрузка этих файлов не требуется. Соседняя подробная запись объясняет сбой служебной операции, например чтения каталога; '
                'он остаётся в дневном счётчике до разбора.')
    if 'rclone exit code' in text or 'attempt ' in text and 'failed' in text:
        return ('Это итог неудачной команды копирования. Один код завершения или итоговый счётчик не объясняет причину. '
                'Найдите рядом более подробную строку с именем файла и описанием сбоя. Уже подтверждённые файлы остаются в журнале, остальные ожидают повтора.')
    if 'safety api unavailable' in text or 'cloud alert observer unavailable' in text:
        return ('Служба не смогла прочитать предупреждения Drime. Днём отправка прерывается и ошибка учитывается в пороге остановки; ночью запись фиксируется без блокировки. '
                'Нужно проверить доступность API Drime; эта запись не доказывает ошибку содержимого копируемых файлов.')
    return ('Для этой записи нет надёжного автоматического пояснения. По её тексту нельзя уверенно назвать причину. '
            'Сохраните время и текст ошибки и разберите соседние сообщения журнала; если служба заблокирована, сначала установите причину, затем запускайте её.')


def error_identity(stamp, message):
    return hashlib.sha256((str(stamp)+'\0'+message).encode('utf-8')).hexdigest()


def error_file(message):
    """Only exact file references; never infer a path from a batch summary."""
    match=re.search(r'\bpath_b64=([A-Za-z0-9+/]+={0,2})(?=[:\s]|$)',message)
    if match:
        try: path=base64.b64decode(match[1],validate=True)
        except (ValueError,binascii.Error): return None
    else:
        match=re.search(r'(?:\bWARNING rclone (?:error|fatal) |\b(?:DAY|NIGHT) error: rclone_error: )([^:\n]+): Failed to (?:copy|open|read|upload)\b',message)
        if not match: return None
        # Non-ASCII log object encoding can be ambiguous; require exact Base64 instead.
        if any(ord(c)<32 or ord(c)>126 for c in match[1]): return None
        path=match[1].encode('ascii')
    path=path.removeprefix(b'/')
    if not path or b'\0' in path or b'..' in path.split(b'/'): return None
    return path


def iso_microseconds(value):
    instant=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if instant.tzinfo is None: raise ValueError('Missing timezone in confirmation')
    return int(instant.timestamp()*1_000_000)


def moscow_time(stamp):
    return dt.datetime.fromtimestamp(stamp/1_000_000,ZoneInfo('Europe/Moscow')).strftime('%Y.%m.%d — %H:%M:%S')


class ErrorResolutions:
    """Read-only evidence: a later confirmed upload or an explicit incident review."""
    def __init__(self):
        self.reviews=read_json(ROOT/'error-resolutions.json')
        self.db=None

    def close(self):
        if self.db is not None: self.db.close()

    def lookup(self, stamp, message):
        pending=dict(resolved=False,label='Не закрыта',
            detail='Подтверждения исправления этой ошибки пока нет. Она требует проверки и может повториться.')
        key=error_identity(stamp,message)
        review=self.reviews.get(key,{}) if isinstance(self.reviews,dict) else {}
        try:
            reviewed_at=iso_microseconds(review.get('at',''))
            reason=review.get('reason')
            if reviewed_at>stamp and isinstance(reason,str) and reason.strip():
                return dict(resolved=True,label='Исправлена',
                    detail='Подтверждено при разборе '+moscow_time(reviewed_at)+' МСК. '+sanitize(reason))
        except (ValueError,TypeError,AttributeError): pass
        path=error_file(message)
        if path is None:
            pending['detail']='В записи нет однозначного имени файла, а отдельного подтверждения исправления нет. Успех другой передачи или перезапуск её не закрывает.'
            return pending
        try:
            if self.db is None:
                self.db=sqlite3.connect((ROOT/'journal.sqlite3').as_uri()+'?mode=ro',uri=True,timeout=1)
                self.db.execute('PRAGMA query_only=ON')
            row=self.db.execute('SELECT present,kind,uploaded=sig,uploaded_at,last_error FROM entries WHERE path=?',(path,)).fetchone()
            if row and row[0] and row[1] in ('file','link') and row[2] and row[4] is None and row[3]:
                copied_at=iso_microseconds(row[3])
                if copied_at>stamp:
                    return dict(resolved=True,label='Исправлена',detail='Успешный повтор подтверждён '+moscow_time(copied_at)+
                        ' МСК. Текущая учтённая версия файла скопирована, ошибки в очереди для неё нет.')
            pending['detail']='После этой ошибки нет подтверждения успешной отправки текущей учтённой версии файла либо он снова ожидает копирования/имеет ошибку.'
        except (OSError,sqlite3.Error,ValueError,TypeError,AttributeError):
            pending['detail']='Не удалось проверить подтверждения в журнале очереди. Исправление пока не подтверждено.'
        return pending


def recent_errors():
    """Last ten matching journal entries, including errors before a manual reset."""
    rows={}
    try:
        # Include native systemd errors as well as Python/rclone error messages.
        for selector in (['--grep',ERROR_PATTERN], ['--priority=err']):
            result=subprocess.run(['/usr/bin/journalctl','--unit',UNIT,'--no-pager',
                '--reverse','--output=json','--lines=10',*selector],
                capture_output=True,text=True,timeout=5)
            # journalctl --grep uses exit 1 for an empty match set.
            if result.returncode==1 and selector[0]=='--grep' and not result.stdout.strip() and not result.stderr.strip():
                continue
            if result.returncode: raise RuntimeError('Journal read failed')
            for line in result.stdout.splitlines():
                row=json.loads(line)
                message=row.get('MESSAGE')
                if not isinstance(message,str): continue
                stamp=int(row['__REALTIME_TIMESTAMP'])
                identity=row.get('__CURSOR') or (stamp,message)
                rows[identity]=(stamp,message)
        errors=[];resolutions=ErrorResolutions()
        try:
            for stamp,message in sorted(rows.values(),key=lambda row:row[0],reverse=True)[:10]:
                resolution=resolutions.lookup(stamp,message)
                key=error_identity(stamp,message)
                message=re.sub(r'^\d{4}-\d{2}-\d{2} [\d:]+(?:[,.]\d+)? ', '', message)
                errors.append(dict(id=key,time=moscow_time(stamp),text=sanitize(message),description=explain_error(message),resolution=resolution))
        finally: resolutions.close()
        return dict(available=True,entries=errors)
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,subprocess.TimeoutExpired):
        # Losing the log view must not hide the start/stop controls.
        return dict(available=False,entries=[])


def status():
    result = systemctl('show', '--property=ActiveState,SubState,MainPID,NRestarts')
    live = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    state = read_json(ROOT/'status.json')
    guard = read_json(ROOT/'safety-state.json')
    # Only fixed-unit, bounded, sanitized errors are exposed after authentication.
    selected = {k: state.get(k) for k in ('updated_at','phase','current_files','pending_files',
        'current_bytes','source_bytes','pending_directories','initial_copy_complete','active','last_operation_error','error_files')}
    selected.update(service=live,day_errors=guard.get('count',0),night_errors=guard.get('night_errors',0),
        safety_stop=(ROOT/'SAFETY_STOP.json').exists(),manual_stop=(ROOT/'MANUAL_STOP.json').exists(),
        reason=guard.get('reason'),error_log=recent_errors(),
        daytime=SafetyGuard.daytime(None),server_time=now())
    selected['eta']=progress.estimate(read_json(ROOT/'progress-history.json'),
        progress.sample(state,guard,read_json(ROOT/'RUNNING.json'),time.time()),
        live.get('ActiveState')=='active',selected['safety_stop'] or selected['manual_stop'],time.time(),state.get('scan_errors',0))
    return selected


def dispatch(request):
    key = request.get('key', '')
    digest = read_json(AUTH).get('key_sha256','')
    if not isinstance(key,str) or len(key)!=64 or not digest or not hmac.compare_digest(hashlib.sha256(key.encode()).hexdigest(),digest):
        return {'ok':False,'error':'access_denied'}
    action = request.get('action')
    if action not in ('status','start','stop'):
        return {'ok':False,'error':'invalid_action'}
    if action=='status': return {'ok':True,'status':status()}
    with (ROOT/'control.lock').open('a') as control_lock:
        fcntl.flock(control_lock,fcntl.LOCK_EX)
        if action=='stop':
            # Write BEFORE stopping: no restart or reboot may undo an operator stop.
            stop_backup()
        else:
            live=status()['service']
            if live.get('ActiveState')=='active': return {'ok':True,'status':status(),'message':'already_running'}
            result=systemctl('stop')
            if result.returncode: raise RuntimeError('Cannot finish previous service run')
            with (ROOT/'daemon.lock').open('a') as daemon_lock:
                fcntl.flock(daemon_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                guard=SafetyGuard(json.loads(CONFIG.read_text()))
                guard.end_run()  # Unit stopped and process lock acquired.
                guard.reset('Explicit operator restart through authenticated web control')
            systemctl('reset-failed')
            result=systemctl('start')
            if result.returncode: raise RuntimeError('Service start failed; inspect journal')
        with (ROOT/'control-audit.jsonl').open('a') as audit:
            audit.write(json.dumps(dict(at=now(),action=action))+'\n')
        return {'ok':True,'status':status(),'message':action}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            raw=self.rfile.readline(2049)
            if len(raw)>2048 or not raw.endswith(b'\n'): raise ValueError('Invalid request size')
            request=json.loads(raw)
            if not isinstance(request,dict): raise ValueError('Invalid request')
            result=dispatch(request)
        except Exception as error:
            # Never log requests: they contain the authentication key.
            print('Control request failed: '+type(error).__name__,flush=True)
            result={'ok':False,'error':'control_unavailable; inspect server journal'}
        try: self.wfile.write(json.dumps(result,ensure_ascii=True).encode()+b'\n')
        except OSError: pass


class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True
    request_queue_size=8
    next_sample=0

    def service_actions(self):
        # Sampling continues without an open browser and never controls the backup.
        if time.monotonic()<self.next_sample:return
        self.next_sample=time.monotonic()+30
        try:
            current=progress.sample(read_json(ROOT/'status.json'),read_json(ROOT/'safety-state.json'),
                read_json(ROOT/'RUNNING.json'),time.time())
            path=ROOT/'progress-history.json';previous=read_json(path)
            updated=progress.record(previous,current)
            if updated!=previous:atomic_json(path,updated)
        except (OSError,ValueError,TypeError,KeyError):
            print('Progress sample unavailable; backup controls remain available',flush=True)


if __name__=='__main__':
    os.umask(0o077)
    if len(sys.argv)>1:
        if sys.argv[1:]!=['stop'] or os.geteuid()!=0:
            raise SystemExit('Usage as root: python3 control.py stop')
        with (ROOT/'control.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            stop_backup()
        print('Backup stopped; persistent manual latch saved')
        raise SystemExit(0)
    pathlib.Path(SOCKET).unlink(missing_ok=True)
    with Server(SOCKET,Handler) as server:
        os.chmod(SOCKET,0o660)
        server.serve_forever(poll_interval=.5)
