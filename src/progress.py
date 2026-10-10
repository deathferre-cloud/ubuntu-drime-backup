"""Bounded progress samples and a conditional estimate for the current queue."""
import datetime as dt
import math
from zoneinfo import ZoneInfo

WINDOW=1800
MIN_WINDOW=120
MAX_AGE=180


def sample(state, guard, run, now):
    try:
        stamp=dt.datetime.fromisoformat(state['updated_at']).timestamp()
        if not 0 <= now-stamp <= MAX_AGE or state['phase'] in ('stopped','safety_stopped','repair_wait','repair_probe'):
            return None
        if not run.get('pid') or not run.get('started_at'):return None
        names=('current_files','current_bytes','pending_files','pending_directories','source_bytes')
        values={k:int(state[k]) for k in names}
        if any(v<0 for v in values.values()):return None
        day=7<=dt.datetime.fromtimestamp(now,ZoneInfo('Europe/Moscow')).hour<19
        regime='day-reduced' if day and guard.get('count',0) else 'day' if day else 'night'
        return dict(at=stamp,condition=[run['pid'],run['started_at'],regime],**values)
    except (KeyError,TypeError,ValueError,OverflowError):return None


def record(history, current):
    if current is None:return {'version':1,'samples':[]}
    rows=history.get('samples',[]) if isinstance(history,dict) else []
    rows=[r for r in rows if isinstance(r,dict) and r.get('condition')==current['condition']
          and isinstance(r.get('at'),(int,float)) and current['at']-WINDOW<=r['at']<=current['at']]
    if rows and current['at']-rows[-1]['at']<20:return {'version':1,'samples':rows[-121:]}
    return {'version':1,'samples':(rows+[current])[-121:]}


def duration(seconds):
    minutes=max(1,math.ceil(seconds/60));days,minutes=divmod(minutes,1440);hours,minutes=divmod(minutes,60)
    parts=[]
    if days:parts.append(str(days)+' дн.')
    if hours:parts.append(str(hours)+' ч')
    if minutes:parts.append(str(minutes)+' мин')
    return ' '.join(parts)


def estimate(history, current, running, blocked, now, scan_errors=0):
    def unavailable(code,text):return dict(state=code,label=text,finish_msk=None,detail='')
    if not running or blocked:return unavailable('paused','Копирование остановлено — прогноз недоступен')
    if current is None:return unavailable('stale','Нет свежей статистики для прогноза')
    remaining=current['pending_files']+current['pending_directories']
    if remaining==0:
        return unavailable('scan_errors' if scan_errors else 'empty',
            'Ожидается устранение ошибок обхода' if scan_errors else 'Очередь файлов и папок пуста')
    rows=record(history,current)['samples']
    if len(rows)<2 or current['at']-rows[0]['at']<MIN_WINDOW:
        return unavailable('collecting','Накапливаем статистику — нужно не менее 2 минут')
    start=rows[0];elapsed=current['at']-start['at']
    try:
        # Net queue progress is conservative when new directories/changes appear.
        files=current['current_files']-start['current_files']
        dirs=start['pending_directories']-current['pending_directories']
        completed=files+dirs
        byte_delta=current['current_bytes']-start['current_bytes']
        remaining_bytes=max(0,current['source_bytes']-current['current_bytes'])
        if completed<=0:
            return unavailable('no_progress','Нет достаточного подтверждённого продвижения для прогноза')
        if completed<10:return unavailable('collecting','Пока слишком мало подтверждённых объектов для прогноза')
        object_rate=completed/elapsed;byte_rate=max(0,byte_delta/elapsed)
        # Byte/sec from tiny files is dominated by API overhead. Applying it to
        # a queue with a much larger mean file size can invent years of work.
        observed_mean=byte_delta/files if files>0 else 0
        pending_mean=remaining_bytes/current['pending_files'] if current['pending_files'] else 0
        comparable=(not remaining_bytes or byte_delta>0 and files>0 and observed_mean>0
                    and .25<=pending_mean/observed_mean<=4)
        seconds=remaining/object_rate
        if comparable and remaining_bytes:seconds=max(seconds,remaining_bytes/byte_rate)
        seconds=math.ceil(seconds/300)*300
        if seconds>10*366*86400:return unavailable('unstable','Темп слишком мал для надёжной даты завершения')
        finish=dt.datetime.fromtimestamp(now+seconds,ZoneInfo('Europe/Moscow')).strftime('%Y.%m.%d — %H:%M МСК')
        method='objects_and_bytes' if comparable else 'objects_only'
        basis=('Учитываются оставшиеся файлы, папки и объём данных; выбирается более долгий из двух расчётов. '
               if comparable else
               'Ориентир по темпу обработки файлов и папок. Размеры недавних и оставшихся файлов несопоставимы '
               'либо ещё нет замера объёма; общий срок требует замеров на более крупных файлах. ')
        return dict(state='estimated',method=method,label=('Около ' if comparable else 'Ориентир: около ')+duration(seconds),remaining_seconds=seconds,
            finish_msk=finish,window_seconds=round(elapsed),objects_per_minute=round(object_rate*60,1),
            bytes_per_second=round(byte_rate),detail=(
                'По подтверждённому продвижению за последние '+duration(elapsed)+'. '
                +basis+
                'При сохранении текущего темпа. Ночной режим, иной размер файлов, новые данные и сбои изменят прогноз. '
                'Финальная запись метаданных и проверка в этот срок не включены.'))
    except (KeyError,TypeError,ValueError,OverflowError,ZeroDivisionError):
        return unavailable('collecting','Статистика обновляется — прогноз пока недоступен')
