#!/bin/bash
# Logical backup of every audit database, shipped off-site to term-c-host.
# Consistent InnoDB snapshot, no table locks. The dump is written and verified
# on local disk, then streamed once over SSH to a forced-command receiver that
# re-checks size, SHA-256 and zstd integrity before keeping it.
set -euo pipefail
umask 077
STATE=${TRAFFIC_CENTRAL_STATE:-/var/lib/traffic-central/state}
KEEP=${TRAFFIC_CENTRAL_BACKUP_KEEP:-2}
TARGET=${TRAFFIC_CENTRAL_BACKUP_TARGET:-auditbackup@203.0.113.109}
KEY=${TRAFFIC_CENTRAL_BACKUP_KEY:-/etc/traffic-central/backup_ed25519}
KNOWN=${TRAFFIC_CENTRAL_BACKUP_KNOWN_HOSTS:-/etc/traffic-central/backup_known_hosts}
remote() {
  ssh -F /dev/null -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$KNOWN" -o GlobalKnownHostsFile=/dev/null "$TARGET" "$@"
}

[ -r "$KEY" ] && [ -r "$KNOWN" ] || { echo backup_key_missing >&2; exit 1; }
mkdir -p "$STATE"
databases=$(mariadb --batch --skip-column-names -e "SELECT TABLE_SCHEMA FROM information_schema.TABLES WHERE TABLE_NAME='audit_schema' AND TABLE_TYPE='BASE TABLE' ORDER BY 1")
[ -n "$databases" ] || { echo no_audit_database >&2; exit 1; }

# A compressed dump has stayed well under a third of the live data; the receiver gates its own space.
need_kb=$(mariadb --batch --skip-column-names -e "SELECT CEIL(SUM(DATA_LENGTH)/3072) FROM information_schema.TABLES WHERE TABLE_SCHEMA IN (SELECT TABLE_SCHEMA FROM information_schema.TABLES WHERE TABLE_NAME='audit_schema')")
[ "$(df -Pk "$STATE" | awk 'NR==2{print $4}')" -gt "$need_kb" ] || { echo "backup_free_space_gate:$STATE" >&2; exit 1; }

stamp=$(date -u +%Y%m%dT%H%M%SZ)
name=audit-$stamp.sql.zst
local_copy=$STATE/.backup-$stamp.sql.zst
trap 'rm -f "$local_copy"' EXIT
started=$(date +%s)
# shellcheck disable=SC2086
mariadb-dump --single-transaction --quick --skip-lock-tables --triggers --routines --hex-blob \
  --databases $databases | zstd -10 -T1 -q -o "$local_copy"

# Only a dump that decompresses and carries the completion marker is uploaded.
zstd -t -q "$local_copy"
zstd -dc "$local_copy" | tail -n 1 | grep -q '^-- Dump completed' || { echo backup_incomplete >&2; exit 1; }
tables=$(zstd -dc "$local_copy" | grep -c '^CREATE TABLE ' || true)
size=$(stat -c %s "$local_copy")
sha=$(sha256sum "$local_copy" | cut -d' ' -f1)

stored=$(remote put "$name" "$size" "$sha" < "$local_copy")
[ "$stored" = "stored $name $size" ] || { echo "backup_upload_unconfirmed:$stored" >&2; exit 1; }
rm -f "$local_copy"
trap - EXIT

kept=$(remote prune "$KEEP")
printf '{"backup":"%s","target":"%s","databases":"%s","bytes":%s,"sha256":"%s","tables":%s,"seconds":%s,"kept":%s}\n' \
  "$name" "${TARGET#*@}" "$(echo $databases | tr ' ' ',')" "$size" "$sha" "$tables" \
  "$(( $(date +%s) - started ))" "$kept"
