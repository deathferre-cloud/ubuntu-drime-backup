<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('session.use_strict_mode', '1');
session_name('UBUNTU_DRIME_BACKUP_CONTROL');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
header('Cache-Control: no-store, private');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
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
$result=bridge($_SESSION['key'],'status');
if (!$result['ok']) deny(503);
$s=$result['status'];$message=$_SESSION['message']??'';unset($_SESSION['message']);
$running=($s['service']['ActiveState']??'')==='active';
$blocked=$s['manual_stop']||$s['safety_stop'];
$fileTotal=is_numeric($s['current_files'])&&is_numeric($s['pending_files']) ? $s['current_files']+$s['pending_files'] : null;
?>
<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ubuntu Drime Backup — управление резервной копией</title>
<style>body{font:17px/1.5 system-ui,sans-serif;background:#111821;color:#e8eef6;margin:0}main{max-width:1350px;margin:35px auto;padding:24px}h1{font-size:27px}section{background:#1d2936;border:1px solid #3a4d63;border-radius:12px;padding:20px;margin:18px 0}.state{font-size:24px;font-weight:700}.muted{color:#afc3d8}button,a{font:inherit}button{padding:14px 20px;border:0;border-radius:8px;cursor:pointer;margin:6px 12px 6px 0;font-weight:700}.stop{background:#ff7770;color:#29100c}.start{background:#7ce1ab;color:#102b1c}a{color:#91c9ff}dt{color:#afc3d8}dd{margin:0 0 12px;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}.notice{border-left:4px solid #7ce1ab;padding-left:16px}code{overflow-wrap:anywhere}.error-log{width:100%;border-collapse:collapse;text-align:left;table-layout:fixed}.error-log th,.error-log td{padding:12px 14px 12px 0;vertical-align:top;border-bottom:1px solid #3a4d63;overflow-wrap:anywhere}.error-log th:first-child{width:205px}.error-log th:nth-child(2){width:96px}.error-log th:nth-child(3){width:34%}.error-log td:first-child{white-space:nowrap}.error-log td:nth-child(2){text-align:center}.error-log td:nth-child(3){font-size:14px;white-space:pre-wrap}.error-log td:nth-child(4){font-size:15px}.error-indicator{display:inline-block;font-size:28px;font-weight:800;line-height:36px;width:36px;border:2px solid currentColor;border-radius:50%}.resolved-mark{color:#7ce1ab;font-weight:800}.open-mark{color:#ff7770;font-weight:800}.status-label{font-size:12px;margin-top:6px}.resolution-note{font-size:13px;color:#afc3d8;border-top:1px dashed #3a4d63;padding-top:10px}.table-scroll{overflow-x:auto}@media(max-width:700px){main{padding:12px}section{padding:14px}.error-log{min-width:1000px}}</style>
<main><p class="muted">Ubuntu → Drime</p><h1>Управление резервной копией</h1>
<?php if ($message): ?><p class="notice"><?=esc($message)?></p><?php endif ?>
<section><div class="state"><?= $blocked ? 'Остановлено и заблокировано' : ($running ? 'Служба работает' : 'Служба остановлена / ожидает перезапуска') ?></div>
<p><?= $s['daytime'] ? 'День: 07:00–19:00 МСК. Автостоп после 5 ошибок; критические сбои останавливают сразу.' : 'Ночь: 19:00–07:00 МСК. Автоматической блокировки нет, ошибки повторяются, письма Drime включены.' ?></p>
<p>Ручной и ранее сработавший дневной стоп сохраняются круглосуточно, включая перезагрузку сервера.</p>
<form method="post" action="<?=PANEL_PATH?>"><input type="hidden" name="csrf" value="<?=esc($_SESSION['csrf'])?>"><button class="stop" name="action" value="stop">Остановить копирование</button><button class="start" name="action" value="start">Снять блокировку и запустить</button></form>
<p class="muted">Запуск остановленной службы подтверждает разбор ошибки и сбрасывает счётчик. Открытие ссылки само по себе ничего не запускает и не останавливает.</p><a href="<?=PANEL_PATH?>">Обновить состояние</a></section>
<section><h2>Ход копирования</h2><dl>
<?php foreach (['Состояние systemd'=>($s['service']['ActiveState']??'?').'/'.($s['service']['SubState']??'?'),'Фаза'=>$s['phase'],'Подтверждено файлов'=>progress_value($s['current_files'],$fileTotal),'Осталось файлов'=>grouped_integer($s['pending_files'],$fileTotal),'Передано байт'=>progress_value($s['current_bytes'],$s['source_bytes']),'Общий объём байт'=>grouped_integer($s['source_bytes'],$s['current_bytes']),'Дневные ошибки до ручного сброса'=>$s['day_errors'].' / 5','Ночные ошибки до ручного сброса'=>$s['night_errors'],'Последнее обновление UTC'=>$s['updated_at'],'Причина остановки / последняя ошибка'=>$s['reason']??$s['last_operation_error']??'—'] as $label=>$value): ?><dt><?=esc($label)?></dt><dd><?=esc($value??'—')?></dd><?php endforeach ?>
</dl><p><?= $s['initial_copy_complete'] ? 'Первичное копирование завершалось: '.esc($s['initial_copy_complete']) : 'Первичная полная копия ещё не завершена.' ?></p></section>
<section id="completion-estimate"><h2>Оценка времени до завершения копирования</h2>
<p class="state"><?=esc($s['eta']['label']??'Прогноз пока недоступен')?></p>
<?php if (!empty($s['eta']['finish_msk'])): ?><dl><dt><?= ($s['eta']['method']??'')==='objects_only' ? 'Ориентир даты по темпу обработки объектов' : 'Ориентировочная дата завершения очереди' ?></dt><dd><?=esc($s['eta']['finish_msk'])?></dd><dt>Измеренный темп</dt><dd><?=esc($s['eta']['objects_per_minute'])?> объектов/мин · <?=esc(number_format($s['eta']['bytes_per_second']/1048576,2,',',' '))?> МиБ/с подтверждённых данных</dd></dl><p class="muted"><?=esc($s['eta']['detail'])?></p>
<?php else: ?><p class="muted">Оценка строится по реальным подтверждениям копирования. Статистика собирается автоматически, даже когда эта страница закрыта.</p><?php endif ?>
</section>
<section><h2>Последние 10 ошибок</h2><p class="muted">Время по Москве (МСК). Самая свежая ошибка — сверху. Показана история журнала, включая уже исправленные ошибки.</p>
<p class="muted"><span class="resolved-mark">✓</span> — исправление подтверждено. <span class="open-mark">!</span> — ошибка не закрыта или её исправление ещё не подтверждено. Основание указано под пояснением; перезапуск сам по себе ошибку не закрывает.</p>
<?php if (empty($s['error_log']['available'])): ?><p>Не удалось прочитать журнал. Обновите страницу; кнопки управления доступны.</p>
<?php elseif (empty($s['error_log']['entries'])): ?><p>В доступном журнале ошибок нет.</p>
<?php else: ?><div class="table-scroll"><table class="error-log"><thead><tr><th scope="col">Время (МСК)</th><th scope="col">Статус</th><th scope="col">Текст ошибки</th><th scope="col">Что это значит и что делать</th></tr></thead><tbody>
<?php foreach ($s['error_log']['entries'] as $entry): $resolution=$entry['resolution']; ?><tr><td><?=esc($entry['time'])?></td><td><span class="error-indicator <?= $resolution['resolved'] ? 'resolved-mark' : 'open-mark' ?>" role="img" aria-label="<?=esc($resolution['label'])?>" title="<?=esc($resolution['detail'])?>"><?= $resolution['resolved'] ? '✓' : '!' ?></span><div class="status-label"><?=esc($resolution['label'])?></div></td><td><?=esc($entry['text'])?></td><td><?=esc($entry['description'])?><p class="resolution-note"><?=esc($resolution['detail'])?></p></td></tr><?php endforeach ?>
</tbody></table></div><?php endif ?><p class="muted"><a href="<?=PANEL_PATH?>">Обновить журнал</a>. Ссылку с ключом храните как пароль.</p></section></main></html>
