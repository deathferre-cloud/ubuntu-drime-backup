<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('session.use_strict_mode', '1');
session_name('UBUNTU_DRIME_BACKUP_CONTROL');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
header('Cache-Control: no-store, private');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
$scriptNonce=base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$scriptNonce'; connect-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
header('Content-Type: text/html; charset=utf-8');
session_start();
const PANEL_PATH = '/backup-control.php';
function bridge(string $key, string $action): array {
    $socket = @stream_socket_client('unix:///run/ubuntu-drime-backup-control/control.sock', $errno, $error, 3);
    if (!$socket) return ['ok'=>false,'error'=>'control_unavailable'];
    stream_set_timeout($socket, 70);
    fwrite($socket, json_encode(['key'=>$key,'action'=>$action])."\n");
    $raw = stream_get_line($socket, 262144, "\n");
    fclose($socket);
    $result = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($result) ? $result : ['ok'=>false,'error'=>'control_unavailable'];
}
function deny(int $code=403): void { http_response_code($code); echo 'Доступ закрыт. Откройте личную ссылку управления.'; exit; }
function esc($value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function grouped_integer($value, $reference=null): string {
    if (!is_numeric($value)) return '—';
    $digits=(string)max(0,(int)$value);
    $referenceDigits=is_numeric($reference) ? strlen((string)max(0,(int)$reference)) : 0;
    $width=(int)(ceil(max(strlen($digits),$referenceDigits)/3)*3);
    return implode(' ',str_split(str_pad($digits,$width,'0',STR_PAD_LEFT),3));
}
function progress_value($done, $total): string {
    if (!is_numeric($done)) return '—';
    $value=grouped_integer($done,$total);
    if (!is_numeric($total) || (float)$total<=0) return $value.' (процент пока не определён)';
    $percent=max(0.0,min(100.0,100.0*(float)$done/(float)$total));
    if ((float)$done<(float)$total) $percent=min(99.99,$percent);
    return $value.' ('.number_format($percent,2,',',' ').'%)';
}
if (!in_array($_SERVER['REQUEST_METHOD'], ['GET','POST'], true)) deny(405);
if (isset($_GET['key'])) {
    if ($_SERVER['REQUEST_METHOD']!=='GET' || !is_string($_GET['key']) || !preg_match('/^[a-f0-9]{64}$/D',$_GET['key'])) deny();
    $auth=bridge($_GET['key'],'status');
    if (!$auth['ok']) deny();
    session_regenerate_id(true);
    $_SESSION=['key'=>$_GET['key'],'csrf'=>bin2hex(random_bytes(32)),'expires'=>time()+28800];
    header('Location: '.PANEL_PATH, true, 303); exit;
}
if (!isset($_SESSION['key'],$_SESSION['csrf'],$_SESSION['expires']) || $_SESSION['expires']<time()) deny();
$message='';
if ($_SERVER['REQUEST_METHOD']==='POST') {
    if (!is_string($_POST['csrf']??null) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) deny();
    $action=$_POST['action']??'';
    if (!is_string($action) || !in_array($action,['start','stop'],true)) deny(400);
    $result=bridge($_SESSION['key'],$action);
    $_SESSION['message']=$result['ok'] ? ($action==='stop' ? 'Копирование остановлено. Ручная блокировка сохранена.' : 'Команда запуска выполнена. Счётчик сброшен только при запуске остановленной службы.') : 'Команда не выполнена. Проверьте журнал службы управления.';
    header('Location: '.PANEL_PATH,true,303); exit;
}
$message=$_SESSION['message']??'';
if (!isset($_GET['refresh'])) unset($_SESSION['message']);
$key=$_SESSION['key'];
// A slow status read must not hold the session lock ahead of a manual stop.
session_write_close();
$result=bridge($key,'status');
if (!$result['ok']) deny(503);
$s=$result['status'];
$running=($s['service']['ActiveState']??'')==='active';
$blocked=$s['manual_stop']||$s['safety_stop'];
$repair=$s['repair']??null;
$fileTotal=is_numeric($s['current_files'])&&is_numeric($s['pending_files']) ? $s['current_files']+$s['pending_files'] : null;
?>
<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ubuntu Drime Backup — управление резервной копией</title>
<style>body{font:17px/1.5 system-ui,sans-serif;background:#111821;color:#e8eef6;margin:0}main{max-width:1350px;margin:35px auto;padding:24px}h1{font-size:27px}section{background:#1d2936;border:1px solid #3a4d63;border-radius:12px;padding:20px;margin:18px 0}.state{font-size:24px;font-weight:700}.muted{color:#afc3d8}button,a{font:inherit}button{padding:14px 20px;border:0;border-radius:8px;cursor:pointer;margin:6px 12px 6px 0;font-weight:700}.stop{background:#ff7770;color:#29100c}.start{background:#7ce1ab;color:#102b1c}a{color:#91c9ff}dt{color:#afc3d8}dd{margin:0 0 12px;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}.notice{border-left:4px solid #7ce1ab;padding-left:16px}code{overflow-wrap:anywhere}.error-log{width:100%;border-collapse:collapse;text-align:left;table-layout:fixed}.error-log th,.error-log td{padding:12px 14px 12px 0;vertical-align:top;border-bottom:1px solid #3a4d63;overflow-wrap:anywhere}.error-log th:first-child{width:205px}.error-log th:nth-child(2){width:96px}.error-log th:nth-child(3){width:34%}.error-log td:first-child{white-space:nowrap}.error-log td:nth-child(2){text-align:center}.error-log td:nth-child(3){font-size:14px;white-space:pre-wrap}.error-log td:nth-child(4){font-size:15px}.error-indicator{display:inline-block;font-size:28px;font-weight:800;line-height:36px;width:36px;border:2px solid currentColor;border-radius:50%}.resolved-mark{color:#7ce1ab;font-weight:800}.open-mark{color:#ff7770;font-weight:800}.status-label{font-size:12px;margin-top:6px}.resolution-note{font-size:13px;color:#afc3d8;border-top:1px dashed #3a4d63;padding-top:10px}.table-scroll{overflow-x:auto}@media(max-width:700px){main{padding:12px}section{padding:14px}.error-log{min-width:1000px}}.refresh-bar{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin:20px 0;color:#afc3d8}.refresh-bar[hidden]{display:none}.refresh-clock{width:52px;height:52px;flex:none;position:relative;color:#7ce1ab}.refresh-clock svg{width:100%;height:100%;transform:rotate(-90deg)}.refresh-track,.refresh-fill{fill:none;stroke-width:3.5}.refresh-track{stroke:#3a4d63}.refresh-fill{stroke:currentColor;stroke-linecap:round;stroke-dasharray:100;stroke-dashoffset:100}.refresh-seconds{position:absolute;inset:0;display:grid;place-items:center;font-weight:700;font-variant-numeric:tabular-nums;font-size:15px}.refresh-copy{flex:1;min-width:220px}.refresh-copy strong{display:block;color:#e8eef6}.refresh-copy small{font-size:13px}.refresh-bar.is-loading .refresh-clock svg{animation:refresh-spin 1s linear infinite}.refresh-bar.is-loading .refresh-fill{stroke-dasharray:24 76;stroke-dashoffset:0!important}.refresh-bar.has-error .refresh-clock{color:#ffb66e}@keyframes refresh-spin{to{transform:rotate(270deg)}}@media(prefers-reduced-motion:reduce){.refresh-bar.is-loading .refresh-clock svg{animation:none}}</style>
<main><p class="muted">Ubuntu → Drime</p><h1>Управление резервной копией</h1>
<div class="refresh-bar" id="refresh-bar" hidden>
<div class="refresh-clock" id="refresh-clock" role="progressbar" aria-label="До обновления данных" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
<svg viewBox="0 0 48 48" aria-hidden="true"><circle class="refresh-track" cx="24" cy="24" r="20"/><circle class="refresh-fill" id="refresh-fill" cx="24" cy="24" r="20" pathLength="100"/></svg><span class="refresh-seconds" id="refresh-seconds" aria-hidden="true">30</span></div>
<div class="refresh-copy"><strong id="refresh-caption">Обновление через 30 с</strong><small id="refresh-result" role="status" aria-live="polite">Данные загружены при открытии страницы.</small></div>
</div><noscript><p class="muted">Для обновления каждые 30 секунд включите JavaScript. Ссылки ручного обновления доступны ниже.</p></noscript>
<?php if ($message): ?><p class="notice"><?=esc($message)?></p><?php endif ?>
<section><div class="state" id="live-service"><?= $blocked ? 'Остановлено и заблокировано' : ($running ? ($repair ? ($repair['label']??'Автоматическое восстановление') : 'Служба работает') : 'Служба остановлена / ожидает перезапуска') ?></div>
<p id="live-period"><?= $s['daytime'] ? 'День: 07:00–19:00 МСК. Автостоп после 5 ошибок; критические сбои останавливают сразу.' : 'Ночь: 19:00–07:00 МСК. Автоматической блокировки нет, ошибки повторяются, письма Drime включены.' ?></p>
<p>Ручной и ранее сработавший дневной стоп сохраняются круглосуточно, включая перезагрузку сервера.</p>
<form method="post" action="<?=PANEL_PATH?>"><input type="hidden" name="csrf" value="<?=esc($_SESSION['csrf'])?>"><button class="stop" name="action" value="stop">Остановить копирование</button><button class="start" name="action" value="start">Снять блокировку и запустить</button></form>
<p class="muted">Запуск остановленной службы подтверждает разбор ошибки и сбрасывает счётчик. Открытие ссылки само по себе ничего не запускает и не останавливает.</p><a data-refresh href="<?=PANEL_PATH?>">Обновить состояние</a></section>
<section id="live-progress"><h2>Ход копирования</h2><dl>
<?php foreach (['Состояние systemd'=>($s['service']['ActiveState']??'?').'/'.($s['service']['SubState']??'?'),'Фаза'=>$s['phase'],'Автоматическое восстановление'=>$repair['label']??'Не требуется','Причина планового повтора'=>$repair['reason']??'—','Подтверждено файлов'=>progress_value($s['current_files'],$fileTotal),'Осталось файлов'=>grouped_integer($s['pending_files'],$fileTotal),'Передано байт'=>progress_value($s['current_bytes'],$s['source_bytes']),'Общий объём байт'=>grouped_integer($s['source_bytes'],$s['current_bytes']),'Дневные ошибки до ручного сброса'=>$s['day_errors'].' / 5','Ночные ошибки до ручного сброса'=>$s['night_errors'],'Последнее обновление UTC'=>$s['updated_at'],'Причина остановки / последняя ошибка'=>$s['reason']??$s['last_operation_error']??'—'] as $label=>$value): ?><dt><?=esc($label)?></dt><dd><?=esc($value??'—')?></dd><?php endforeach ?>
</dl><p><?= $s['initial_copy_complete'] ? 'Первичное копирование завершалось: '.esc($s['initial_copy_complete']) : 'Первичная полная копия ещё не завершена.' ?></p></section>
<section id="completion-estimate"><h2>Оценка времени до завершения копирования</h2>
<p class="state"><?=esc($s['eta']['label']??'Прогноз пока недоступен')?></p>
<?php if (!empty($s['eta']['finish_msk'])): ?><dl><dt><?= ($s['eta']['method']??'')==='objects_only' ? 'Ориентир даты по темпу обработки объектов' : 'Ориентировочная дата завершения очереди' ?></dt><dd><?=esc($s['eta']['finish_msk'])?></dd><dt>Измеренный темп</dt><dd><?=esc($s['eta']['objects_per_minute'])?> объектов/мин · <?=esc(number_format($s['eta']['bytes_per_second']/1048576,2,',',' '))?> МиБ/с подтверждённых данных</dd></dl><p class="muted"><?=esc($s['eta']['detail'])?></p>
<?php else: ?><p class="muted">Оценка строится по реальным подтверждениям копирования. Статистика собирается автоматически, даже когда эта страница закрыта.</p><?php endif ?>
</section>
<section id="live-errors"><h2>Последние 10 ошибок</h2><p class="muted">Время по Москве (МСК). Самая свежая ошибка — сверху. Показана история журнала, включая уже исправленные ошибки.</p>
<p class="muted"><span class="resolved-mark">✓</span> — исправление подтверждено. <span class="open-mark">!</span> — ошибка не закрыта или её исправление ещё не подтверждено. Основание указано под пояснением; перезапуск сам по себе ошибку не закрывает.</p>
<?php if (empty($s['error_log']['available'])): ?><p>Не удалось прочитать журнал. Обновите страницу; кнопки управления доступны.</p>
<?php elseif (empty($s['error_log']['entries'])): ?><p>В доступном журнале ошибок нет.</p>
<?php else: ?><div class="table-scroll"><table class="error-log"><thead><tr><th scope="col">Время (МСК)</th><th scope="col">Статус</th><th scope="col">Текст ошибки</th><th scope="col">Что это значит и что делать</th></tr></thead><tbody>
<?php foreach ($s['error_log']['entries'] as $entry): $resolution=$entry['resolution']; ?><tr><td><?=esc($entry['time'])?></td><td><span class="error-indicator <?= $resolution['resolved'] ? 'resolved-mark' : 'open-mark' ?>" role="img" aria-label="<?=esc($resolution['label'])?>" title="<?=esc($resolution['detail'])?>"><?= $resolution['resolved'] ? '✓' : '!' ?></span><div class="status-label"><?=esc($resolution['label'])?></div></td><td><?=esc($entry['text'])?></td><td><?=esc($entry['description'])?><p class="resolution-note"><?=esc($resolution['detail'])?></p></td></tr><?php endforeach ?>
</tbody></table></div><?php endif ?><p class="muted"><a data-refresh href="<?=PANEL_PATH?>">Обновить журнал</a>. Ссылку с ключом храните как пароль.</p></section></main>
<script nonce="<?=esc($scriptNonce)?>">
(() => {
    'use strict';
    const interval = 30000;
    const bar = document.getElementById('refresh-bar');
    const clock = document.getElementById('refresh-clock');
    const fill = document.getElementById('refresh-fill');
    const seconds = document.getElementById('refresh-seconds');
    const caption = document.getElementById('refresh-caption');
    const result = document.getElementById('refresh-result');
    const ids = ['live-service', 'live-period', 'live-progress', 'completion-estimate', 'live-errors'];
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const timeFormat = new Intl.DateTimeFormat('ru-RU', {timeZone: 'Europe/Moscow', hour: '2-digit', minute: '2-digit', second: '2-digit'});
    let deadline = performance.now() + interval;
    let loading = false;
    let stopped = false;
    let controller = null;
    let shownSecond = -1;
    bar.hidden = false;

    async function refresh() {
        if (loading || stopped) return;
        loading = true;
        bar.classList.add('is-loading');
        caption.textContent = 'Обновляем данные…';
        seconds.textContent = '…';
        clock.setAttribute('aria-valuetext', 'Обновляем данные');
        controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 15000);
        try {
            const url = new URL(<?=json_encode(PANEL_PATH)?>, window.location.origin);
            url.searchParams.set('refresh', '1');
            const response = await fetch(url, {method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal});
            if (response.status === 403) {
                stopped = true;
                throw new Error('session_expired');
            }
            if (!response.ok) throw new Error('unavailable');
            const page = new DOMParser().parseFromString(await response.text(), 'text/html');
            const replacements = ids.map(id => [document.getElementById(id), page.getElementById(id)]);
            if (replacements.some(([current, next]) => !current || !next)) throw new Error('invalid_page');
            if (stopped) return;
            for (const [current, next] of replacements) {
                const scrollLeft = current.querySelector('.table-scroll')?.scrollLeft || 0;
                current.replaceWith(next);
                const table = next.querySelector('.table-scroll');
                if (table) table.scrollLeft = scrollLeft;
            }
            bar.classList.remove('has-error');
            result.textContent = 'Страница обновлена в ' + timeFormat.format(new Date()) + ' МСК';
        } catch (error) {
            if (stopped && error.message !== 'session_expired') return;
            bar.classList.add('has-error');
            result.textContent = error.message === 'session_expired'
                ? 'Сеанс истёк. Откройте личную ссылку управления заново.'
                : 'Не удалось обновить данные. Показаны предыдущие; повтор через 30 с.';
        } finally {
            window.clearTimeout(timeout);
            controller = null;
            loading = false;
            bar.classList.remove('is-loading');
            deadline = performance.now() + interval;
            shownSecond = -1;
            if (stopped) {
                caption.textContent = 'Автообновление приостановлено';
                seconds.textContent = '—';
            }
        }
    }

    function tick(now) {
        if (!stopped && !loading) {
            const remaining = Math.max(0, deadline - now);
            const second = Math.ceil(remaining / 1000);
            const progress = Math.min(100, Math.max(0, 100 * (1 - remaining / interval)));
            if (!reducedMotion.matches || second !== shownSecond) fill.style.strokeDashoffset = String(100 - progress);
            if (second !== shownSecond) {
                shownSecond = second;
                seconds.textContent = String(second);
                caption.textContent = 'Обновление через ' + second + ' с';
                clock.setAttribute('aria-valuenow', String(Math.floor(progress)));
                clock.setAttribute('aria-valuetext', 'Обновление через ' + second + ' секунд');
            }
            if (remaining === 0) void refresh();
        }
        if (!stopped) window.requestAnimationFrame(tick);
    }
    document.addEventListener('click', event => {
        const link = event.target.closest('a[data-refresh]');
        if (!link || stopped || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button !== 0) return;
        event.preventDefault();
        void refresh();
    });
    document.querySelector('form').addEventListener('submit', () => {
        stopped = true;
        if (controller) controller.abort();
        caption.textContent = 'Выполняем команду…';
        seconds.textContent = '…';
    });
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden && performance.now() >= deadline) void refresh();
    });
    window.requestAnimationFrame(tick);
})();
</script>
</html>
