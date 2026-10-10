"""Shared, read-only resolution evidence for the safety budget and web panel."""
import base64
import binascii
import copy
import datetime as dt
import hashlib
import json
import pathlib
import re
import sqlite3
from zoneinfo import ZoneInfo

AUTOMATIC_KINDS={'rclone_error','rclone_exit','transfer_error','scan_error','guard_api_error','repair_probe_error'}


def read_json(path):
    try:return json.loads(path.read_text())
    except (OSError,ValueError):return {}


def event_key(value):
    return hashlib.sha256(str(value).encode('utf8')).hexdigest()


def sanitize(value):
    value = re.sub(r'(https?://[^\s"?]+)\?[^\s"]+', r'\1?[redacted]', str(value))
    value = re.sub(r'(?i)(bearer\s+|access_token[=:]\s*)[^\s,;]+', r'\1[redacted]', value)
    return value[:1200]



def error_identity(stamp, message):
    return hashlib.sha256((str(stamp)+'\0'+message).encode('utf-8')).hexdigest()


def error_file(message):
    """Only exact file references; never infer a path from a batch summary."""
    match=re.search(r'\bpath_b64=([A-Za-z0-9+/]+={0,2})(?=[:\s]|$)',message)
    if match:
        try: path=base64.b64decode(match[1],validate=True)
        except (ValueError,binascii.Error): return None
    else:
        match=re.search(r'(?:\bWARNING rclone (?:error|fatal) |\b(?:DAY|NIGHT) error: rclone_error: )([^:\n]+): (?:Failed to (?:copy|open|read|upload)|Couldn\x27t move)\b',message)
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
    def __init__(self, root, guard_data=None):
        self.root=pathlib.Path(root)
        self.guard_data=guard_data if guard_data is not None else read_json(self.root/'safety-state.json')
        self.reviews=read_json(self.root/'error-resolutions.json')
        self.db=None

    def close(self):
        if self.db is not None: self.db.close()

    def lookup(self, stamp, message, event_id=None, allow_automatic=True):
        pending=dict(resolved=False,label='Не закрыта',
            detail='Подтверждения исправления этой ошибки пока нет. Она требует проверки и может повториться.')
        key=error_identity(stamp,message)
        explicit_event=event_id is not None
        match=re.search(r'\[error_id=([0-9a-f]{64})\]$',message)
        event_id=event_id or (match[1] if match else None)
        event=next((e for e in self.guard_data.get('events',[]) if event_key(e['id'])==event_id),None) if event_id else None
        if event and not explicit_event:
            expected='WARNING '+event.get('period','day').upper()+' error: '+event['kind']+': '+sanitize(event['detail'])+' [error_id='+event_id+']'
            normalized=re.sub(r'^\d{4}-\d{2}-\d{2} [\d:]+(?:[,.]\d+)? ', '', message)
            if normalized!=expected: event=None;event_id=None
        elif not event and not explicit_event: event_id=None
        if event and event.get('resolved_at'):
            return dict(resolved=True,label='Исправлена',detail=event.get('resolution_detail','Исправление подтверждено журналом защиты.'))
        review=self.reviews.get('event:'+event_id,self.reviews.get(key,{})) if event_id and isinstance(self.reviews,dict) else self.reviews.get(key,{}) if isinstance(self.reviews,dict) else {}
        # Security alerts cannot be closed merely because a file was copied.
        if event and event.get('kind') not in AUTOMATIC_KINDS: allow_automatic=False
        if re.search(r'error: (?:cloud_alert|cloud_observation_gap|unclean_night_restart):',message): allow_automatic=False
        try:
            reviewed_at=iso_microseconds(review.get('at',''))
            reason=review.get('reason')
            if reviewed_at>stamp and isinstance(reason,str) and reason.strip():
                return dict(resolved=True,label='Исправлена',
                    detail='Подтверждено при разборе '+moscow_time(reviewed_at)+' МСК. '+sanitize(reason))
        except (ValueError,TypeError,AttributeError): pass
        incident=re.search(r'\[incident_id=([0-9a-f]{32})\]',message) if allow_automatic else None
        incident_id=incident[1] if incident else review.get('incident_id') if isinstance(review,dict) else None
        if isinstance(incident_id,str) and re.fullmatch(r'[0-9a-f]{32}',incident_id):
            try:
                if self.db is None:
                    self.db=sqlite3.connect((self.root/'journal.sqlite3').as_uri()+'?mode=ro',uri=True,timeout=1)
                    self.db.execute('PRAGMA query_only=ON')
                row=self.db.execute('SELECT resolved_at,error FROM transfer_incidents WHERE id=?',(incident_id,)).fetchone()
                total,remaining=self.db.execute('SELECT COUNT(*),SUM(resolved_at IS NULL) FROM incident_files WHERE incident_id=?',(incident_id,)).fetchone()
                if row and row[1] and total and not remaining and row[0]:
                    return dict(resolved=True,label='Исправлена',detail='Повтор этой пачки подтверждён '+moscow_time(iso_microseconds(row[0]))+
                        ' МСК. Все её файлы получили подтверждение отправки. Новые изменения файлов учитываются отдельно.')
                pending['detail']='У этой записи есть связь с конкретной пачкой. Подтверждения ожидают: '+str(remaining if total else 'проверка продолжается')+'. Успех другой пачки её не закрывает.'
                return pending
            except (OSError,sqlite3.Error,ValueError,TypeError,AttributeError):
                pending['detail']='Связь с пачкой записана, но проверить её подтверждения сейчас не удалось.'
                return pending
        if not allow_automatic: return pending
        path=error_file(message)
        if path is None:
            pending['detail']='В записи нет однозначного имени файла, а отдельного подтверждения исправления нет. Успех другой передачи или перезапуск её не закрывает.'
            return pending
        try:
            if self.db is None:
                self.db=sqlite3.connect((self.root/'journal.sqlite3').as_uri()+'?mode=ro',uri=True,timeout=1)
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




def refresh_error_state(data, root):
    """Pure projection: retain unresolved events and close only proven recoveries.

    The daemon persists this result. The panel can use the same projection without
    writing the daemon's state or taking away a manual/security latch.
    """
    result=copy.deepcopy(data)
    result.setdefault('events',[])
    if result.get('version',1)==1:
        # Older releases bounded *all* events to 100. Missing history is not proof
        # of recovery: preserve any unrepresented count as an unresolved item.
        for period,field,total in (('day','count','day_total'),('night','night_errors','night_total')):
            recorded=sum(e.get('weight',1) for e in result['events'] if e.get('period','day')==period)
            old_count=int(result.get(field,0));result[total]=max(recorded,old_count)
            if old_count>recorded:
                result['events'].append(dict(id='legacy-unattributed-'+period,kind='legacy_unattributed',
                    detail='Старая версия сохранила счётчик, но не сохранила все события; нужен разбор истории.',
                    at=result.get('updated_at',dt.datetime.now(dt.timezone.utc).isoformat()),period=period,weight=old_count-recorded))
        result['version']=2
    reader=ErrorResolutions(root,guard_data=result)
    try:
        for event in result['events']:
            if event.get('resolved_at'):continue
            try:stamp=iso_microseconds(event['at'])
            except (ValueError,KeyError,TypeError,AttributeError):continue
            message='WARNING '+event.get('period','day').upper()+' error: '+event['kind']+': '+event['detail']
            proof=reader.lookup(stamp,message,event_id=event_key(event['id']),allow_automatic=event['kind'] in AUTOMATIC_KINDS)
            health={'guard_api_error':'observer_healthy_at','scan_error':'scan_healthy_at'}.get(event['kind'])
            if health and not proof['resolved']:
                try:
                    if iso_microseconds(result.get(health,''))>stamp:
                        proof=dict(resolved=True,detail=('Чтение правил и полного доступного журнала Drime восстановлено ' if health=='observer_healthy_at' else 'Полный обход всех выбранных корней завершён без ошибок ')+moscow_time(iso_microseconds(result[health]))+' МСК.')
                except (ValueError,TypeError,AttributeError):pass
            if proof['resolved']:
                event.update(resolved_at=dt.datetime.now(dt.timezone.utc).isoformat(),resolution_detail=proof['detail'])
    finally:reader.close()
    opened=[e for e in result['events'] if not e.get('resolved_at')]
    closed=[e for e in result['events'] if e.get('resolved_at')][-100:]
    result['events']=opened+closed
    result['count']=sum(e.get('weight',1) for e in opened if e.get('period','day')=='day')
    result['night_errors']=sum(e.get('weight',1) for e in opened if e.get('period','day')=='night')
    return result
