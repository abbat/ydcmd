#!/bin/sh

set -e

DAYS_TO_KEEP="31"
LOCAL_PATH="/home/backup/server"
REMOTE_PATH="disk:/backup/server"

INCLUDE="
/etc/
/root/
/var/spool/cron/crontabs/
"

EXCLUDE="
/tmp/
/var/tmp/
"

umask 0066

DATE_STR=$(date +%Y-%m-%dT%H-%M-%S)
ARCHIVE_NAME="${LOCAL_PATH}/${DATE_STR}.tar.xz"

INCLUDE_FILE="/tmp/include.list.$$"
EXCLUDE_FILE="/tmp/exclude.list.$$"

echo "${INCLUDE}" > "${INCLUDE_FILE}"
echo "${EXCLUDE}" > "${EXCLUDE_FILE}"

XZ_OPT="-9" tar --create --absolute-names --preserve-permissions --xz \
    --files-from   "${INCLUDE_FILE}" \
    --exclude-from "${EXCLUDE_FILE}" \
    --file         "${ARCHIVE_NAME}"

rm -f "${INCLUDE_FILE}"
rm -f "${EXCLUDE_FILE}"

find "${LOCAL_PATH}" -type f -mtime +${DAYS_TO_KEEP} -print0 | xargs -r -0 rm

/usr/bin/ydcmd --rsync --quiet put "${LOCAL_PATH}/" "${REMOTE_PATH}/"
