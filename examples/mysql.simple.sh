#!/bin/sh

set -e

DAYS_TO_KEEP="31"
LOCAL_PATH="/home/backup/mysql"
REMOTE_PATH="disk:/backup/mysql"

umask 0077

DATE_STR=$(date +%Y-%m-%d)
ARCHIVE_PATH="${LOCAL_PATH}/${DATE_STR}"

mkdir -p "${ARCHIVE_PATH}"

for DATABASE in $(/usr/bin/mysql -s --execute="SHOW DATABASES")
do
    if [ "${DATABASE}" != "information_schema" -a "${DATABASE}" != "performance_schema" ]; then
        TIME_STR=$(date +%H-%M-%S)
        DUMP_NAME="${ARCHIVE_PATH}/${DATABASE}_${TIME_STR}.sql"
        /usr/bin/mysqldump      \
            --events            \
            --add-drop-database \
            --add-drop-table    \
            --databases         \
            --routines          \
            --triggers          \
            --create-options    \
            --complete-insert   \
            --quick             \
            --add-locks         \
            "${DATABASE}" > "${DUMP_NAME}"
    fi
done

xz -9 "${ARCHIVE_PATH}"/*.sql

find "${LOCAL_PATH}" -maxdepth 1 -mindepth 1 -type d -mtime +${DAYS_TO_KEEP} -print0 | xargs -r -0 rm -rf

/usr/bin/ydcmd --rsync --quiet put "${LOCAL_PATH}/" "${REMOTE_PATH}/"
