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
from error_state import (ErrorResolutions as SharedErrorResolutions, error_identity, error_file,
                         iso_microseconds, moscow_time, refresh_error_state, event_key)

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
    if 'corrupted on transfer: sizes differ' in text:
        return ('Размер переданного файла не совпал с размером исходника при проверке. Такое бывает, когда журнал продолжает расти во время копирования; '
                'сама эта строка не доказывает повреждение диска. Файл остаётся в очереди до подтверждённой стабильной отправки. '
                'После успешного повтора соответствующая ошибка становится зелёной и освобождает лимит.')
    if 'folder with same name already exists' in text:
        return ('Drime сообщил, что папка с таким именем уже существует, и отклонил её создание. '
                'Это конфликт создания папки, а не доказательство потери файлов. Обработка этого случая уже добавлена в клиент. '
                'Если запись новая и повторяется после обновления, нужно проверить точный путь и возможные одноимённые папки; удалять их наугад не следует.')
    if any(word in text for word in ('sha256','sha-256')) and any(word in text for word in ('mismatch','не совп')):
        return ('Скачанный контрольный файл не совпал с исходным по контрольной сумме. Служба не считает такую копию исправной и возвращает файл в очередь. '
                'Нужно проверить конкретный исходник и его облачную версию; до проверки не полагайтесь на эту копию.')
    if 'error limit reached' in text or 'error budget exhausted' in text:
        return ('Одновременно осталось 5 неустранённых дневных ошибок. Сработала защита и остановила копирование. '
                'Сначала разберите предыдущие ошибки в таблице и устраните причину, затем нажмите «Снять блокировку и запустить».')
    if 'scheduled recovery' in text or 'no observable progress' in text or 'stall deadline' in text:
        return ('Клиент долго не показывал наблюдаемого продвижения. У пачек каталогов байтовые счётчики остаются нулевыми даже во время работы. '
                'Теперь каталоги отправляются небольшими группами. При повторном зависании завершается только текущая команда, очередь сохраняется, '
                'затем следует пауза 10 минут, проверка доступа к Drime и повтор небольшой пачки. Ручной стоп и защитные блокировки не снимаются. '
                'Старые записи SAFETY STOP относятся к прежнему правилу; фактический режим и время повтора показаны в текущем состоянии.')
    if 'maximum command duration' in text:
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
    if 'no valid entries to move' in text:
        return ('Drime не подтвердил перенос предыдущей облачной версии файла в историю. Иногда перенос уже выполнен, '
                'но ответ потерян и повторный запрос возвращает эту ошибку. Клиент проверяет исходный ID файла в точной папке назначения; '
                'только это подтверждает выполненный перенос. Если подтверждения нет, текущий файл остаётся в очереди; '
                'обходить сохранение истории или считать такой ответ успешным без проверки нельзя.')
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
    if re.search(r'(?<![\d])0 unconfirmed files retained',text) or 'all batch files were individually confirmed' in text:
        return ('Команда завершилась с ошибкой, но все файлы этой пачки уже получили отдельные подтверждения успешной отправки. '
                'Повторная загрузка этих файлов не требуется. Соседняя подробная запись объясняет сбой служебной операции, например чтения каталога; '
                'он исключается из счётчика после подтверждённого исправления соответствующей операции.')
    pending=re.search(r'\boperation failed;\s*(\d+) unconfirmed files retained',text)
    if pending:
        cause=(' Причиной было чтение предупреждений Drime, а не установленная ошибка содержимого этих файлов.'
               if 'cloud alert observer unavailable' in text else '')
        return ('Пачка прервана: '+pending[1]+' файлов пока не получили подтверждения успешной отправки. '
                'Они сохранены в очереди для повтора; уже подтверждённые файлы не отменены.'+cause+
                ' Эта запись не означает, что все перечисленные файлы повреждены или потеряны.')
    if 'cycle paused after error; durable budget' in text:
        return ('Цикл временно прерван после ошибки, уже учтённой в дневном счётчике. Подробная причина находится в соседней записи журнала. '
                'Через минуту служба повторяет попытку; при достижении дневного порога сохраняется блокировка до ручного разбора. '
                'Эта итоговая строка не добавляет ещё одну ошибку в счётчик.')
    if 'rclone exit code' in text or 'attempt ' in text and 'failed' in text:
        return ('Это итог неудачной команды копирования. Один код завершения или итоговый счётчик не объясняет причину. '
                'Найдите рядом более подробную строку с именем файла и описанием сбоя. Уже подтверждённые файлы остаются в журнале, остальные ожидают повтора.')
    if 'safety api unavailable' in text or 'cloud alert observer unavailable' in text:
        return ('Служба не смогла прочитать предупреждения Drime. Днём отправка прерывается и ошибка учитывается в пороге остановки; ночью запись фиксируется без блокировки. '
                'Нужно проверить доступность API Drime; эта запись не доказывает ошибку содержимого копируемых файлов.')
    return ('Для этой записи нет надёжного автоматического пояснения. По её тексту нельзя уверенно назвать причину. '
            'Сохраните время и текст ошибки и разберите соседние сообщения журнала; если служба заблокирована, сначала установите причину, затем запускайте её.')


class ErrorResolutions:
    # Keep the controller's injectable ROOT; implementation is shared with safety.
    def __new__(cls):
        return SharedErrorResolutions(ROOT)


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
    guard = refresh_error_state(read_json(ROOT/'safety-state.json'),ROOT)
    # Only fixed-unit, bounded, sanitized errors are exposed after authentication.
    selected = {k: state.get(k) for k in ('updated_at','phase','current_files','pending_files',
        'current_bytes','source_bytes','pending_directories','initial_copy_complete','active','last_operation_error','error_files','repair')}
    selected.update(service=live,day_errors=guard.get('count',0),night_errors=guard.get('night_errors',0),
        safety_stop=(ROOT/'SAFETY_STOP.json').exists(),manual_stop=(ROOT/'MANUAL_STOP.json').exists(),
        reason=guard.get('reason'),error_log=recent_errors(),
        daytime=SafetyGuard.daytime(None),server_time=now())
    unresolved=[e for e in guard.get('events',[]) if not e.get('resolved_at')]
    selected['pending_errors']={'total':sum(e.get('weight',1) for e in unresolved),'entries':[
        dict(id=event_key(e['id']),time=moscow_time(iso_microseconds(e['at'])),period=e.get('period','day'),
             weight=e.get('weight',1),text=sanitize(e['detail']),description=explain_error(e['kind']+': '+e['detail']))
        for e in sorted(unresolved,key=lambda e:e.get('at',''),reverse=True)[:20]]}
    selected['resolved_day_errors']=max(0,guard.get('day_total',0)-guard.get('count',0))
    selected['resolved_night_errors']=max(0,guard.get('night_total',0)-guard.get('night_errors',0))
    selected['eta']=progress.estimate(read_json(ROOT/'progress-history.json'),
        progress.sample(state,guard,read_json(ROOT/'RUNNING.json'),time.time()),
        live.get('ActiveState')=='active',selected['safety_stop'] or selected['manual_stop'],time.time(),state.get('scan_errors',0))
    repair=selected.get('repair')
    if repair:
        when=repair.get('retry_at')
        repair['retry_msk']=dt.datetime.fromtimestamp(when,ZoneInfo('Europe/Moscow')).strftime('%Y.%m.%d — %H:%M:%S') if when else None
        repair['label']=('Пауза восстановления: повтор '+repair['retry_msk']+' МСК') if when else 'Проверка восстановления: повтор небольшой пачки'
        if selected['safety_stop'] or selected['manual_stop'] or live.get('ActiveState')!='active':
            repair['label']='Автоповтор приостановлен: служба остановлена или заблокирована'
        else:
            selected['eta']=dict(state='repair',label=repair['label'],finish_msk=None,detail='')
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
                # The web request must remain bounded; daemon retries use the full profile.
                config=json.loads(CONFIG.read_text())
                config.update(cloud_guard_attempts=1,cloud_guard_connect_timeout=5,cloud_guard_timeout=10)
                guard=SafetyGuard(config)
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
