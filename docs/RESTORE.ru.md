# Восстановление в отдельный каталог

1. Выберите актуальные файлы или конкретную версию из истории.
2. Скачайте в отдельный пустой каталог, а не поверх работающего сервера.
3. Выберите подходящий по времени манифест метаданных.
4. Проверьте отчёт утилиты без `--apply`, затем примените метаданные.
5. Проверьте содержимое, права, ссылки и работу приложений перед переносом.

```bash
sudo mkdir -p /restore/drime
sudo /opt/ubuntu-drime-backup/rclone-fast copy drime: /restore/drime \
  --config /etc/ubuntu-drime-backup/rclone.conf \
  --exclude '/.ubuntu-drime-backup/**'

# Сначала посмотрите доступные UTC-каталоги и выберите нужный:
sudo /opt/ubuntu-drime-backup/rclone-fast lsf \
  drime:.ubuntu-drime-backup/server/metadata/ \
  --config /etc/ubuntu-drime-backup/rclone.conf

# Замените SELECTED_UTC на выбранный каталог; копируйте манифест отдельно.
sudo /opt/ubuntu-drime-backup/rclone-fast copyto \
  drime:.ubuntu-drime-backup/server/metadata/SELECTED_UTC/filesystem.jsonl.gz \
  /restore/filesystem.jsonl.gz --config /etc/ubuntu-drime-backup/rclone.conf

sudo python3 /opt/ubuntu-drime-backup/restore_metadata.py \
  --root /restore/drime --manifest /restore/filesystem.jsonl.gz

sudo python3 /opt/ubuntu-drime-backup/restore_metadata.py \
  --root /restore/drime --manifest /restore/filesystem.jsonl.gz --apply
```

Если для загрузки нужен `network_wrapper`, запускайте скачивание через него так же, как настроена служба. Манифест содержит исходные UID/GID, mode, времена, xattrs и назначения ссылок. Пользователей с нужными UID/GID и приложения нужно подготовить отдельно. Сокеты и устройства утилита не создаёт. ACL, если доступны как xattrs и разрешены файловой системой, обрабатываются вместе с xattrs; это не полная замена проверки конкретного приложения.

Утилита отказывается работать с `/` как корнем восстановления и не идёт через символические ссылки. Существующий обычный файл заменяется ссылкой только если его байты точно равны сохранённому тексту назначения. При отсутствующих данных возвращается ошибка. Сначала устраните её, а не переносите неполную копию в рабочие каталоги.

Этот выпуск не выполняет автоматическое восстановление загрузчика, разметки дисков, пакетов Ubuntu или согласованного состояния работающих БД. Дампы БД восстанавливаются средствами соответствующей СУБД.
