#!/bin/bash
# Logical backup of every audit database to the archive mount (legacy-host).
# Consistent InnoDB snapshot, no table locks. The dump is written and verified
# on local disk and crosses the network exactly once; reading it back over the
# mount to verify would triple the transfer.
set -euo pipefail
umask 077
ROOT=${TRAFFIC_CENTRAL_ARCHIVE:-/var/lib/traffic-central/archive}
STATE=${TRAFFIC_CENTRAL_STATE:-/var/lib/traffic-central/state}
DEST=$ROOT/_backup
KEEP=${TRAFFIC_CENTRAL_BACKUP_KEEP:-2}

mountpoint -q "$ROOT" || { echo cold_archive_mount_required >&2; exit 1; }
mkdir -p "$DEST"
databases=$(mariadb --batch --skip-column-names -e "SELECT TABLE_SCHEMA FROM information_schema.TABLES WHERE TABLE_NAME='audit_schema' AND TABLE_TYPE='BASE TABLE' ORDER BY 1")
[ -n "$databases" ] || { echo no_audit_database >&2; exit 1; }

# A compressed dump has stayed well under a third of the live data; require that much room on both sides.
need_kb=$(mariadb --batch --skip-column-names -e "SELECT CEIL(SUM(DATA_LENGTH)/3072) FROM information_schema.TABLES WHERE TABLE_SCHEMA IN (SELECT TABLE_SCHEMA FROM information_schema.TABLES WHERE TABLE_NAME='audit_schema')")
for place in "$STATE" "$DEST"; do
  [ "$(df -Pk "$place" | awk 'NR==2{print $4}')" -gt "$need_kb" ] || { echo "backup_free_space_gate:$place" >&2; exit 1; }
done

stamp=$(date -u +%Y%m%dT%H%M%SZ)
local_copy=$STATE/.backup-$stamp.sql.zst
partial=$DEST/.audit-$stamp.sql.zst.part
final=$DEST/audit-$stamp.sql.zst
trap 'rm -f "$local_copy" "$partial"' EXIT
started=$(date +%s)
# shellcheck disable=SC2086
mariadb-dump --single-transaction --quick --skip-lock-tables --triggers --routines --hex-blob \
  --databases $databases | zstd -10 -T1 -q -o "$local_copy"

# Only a dump that decompresses and carries the completion marker is uploaded.
zstd -t -q "$local_copy"
zstd -dc "$local_copy" | tail -n 1 | grep -q '^-- Dump completed' || { echo backup_incomplete >&2; exit 1; }
tables=$(zstd -dc "$local_copy" | grep -c '^CREATE TABLE ' || true)
size=$(stat -c %s "$local_copy")

cp "$local_copy" "$partial"
sync "$partial"
[ "$(stat -c %s "$partial")" = "$size" ] || { echo backup_upload_size_mismatch >&2; exit 1; }
mv "$partial" "$final"
rm -f "$local_copy"
trap - EXIT

ls -1t "$DEST"/audit-*.sql.* 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do rm -f "$old"; done
printf '{"backup":"%s","databases":"%s","bytes":%s,"tables":%s,"seconds":%s,"kept":%s}\n' \
  "$(basename "$final")" "$(echo $databases | tr ' ' ',')" "$size" "$tables" \
  "$(( $(date +%s) - started ))" "$(ls -1 "$DEST"/audit-*.sql.* | wc -l)"
