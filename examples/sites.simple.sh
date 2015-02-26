#!/bin/sh

set -e

DAYS_TO_KEEP="31"
LOCAL_PATH="/home/backup/sites"
REMOTE_PATH="disk:/backup/sites"

umask 0077

DATE_STR=$(date +%Y-%m-%d)
ARCHIVE_PATH="${LOCAL_PATH}/${DATE_STR}"

mkdir -p "${ARCHIVE_PATH}"

cd "/var/www"

for SITE in *
do
    if [ "${SITE}" != "httpd-logs" -a "${SITE}" != "nginx-logs" -a "${SITE}" != "httpd-cert" -a "${SITE}" != "backup" -a "${SITE}" != "lost+found" ]; then
        TIME_STR=$(date +%H-%M-%S)
        ARCHIVE_NAME="${ARCHIVE_PATH}/${SITE}_${TIME_STR}.tar.7z"
        tar --create --preserve-permissions --file - \
            "${SITE}"                                \
            --exclude="${SITE}/data/logs"            \
            --exclude="${SITE}/data/bin-tmp"         \
            --exclude="${SITE}/data/tmp"             \
            | /usr/bin/7zr a -si -y -v256m -mx=9 -mmt=4 "${ARCHIVE_NAME}" > /dev/null
    fi
done

find "${LOCAL_PATH}" -maxdepth 1 -mindepth 1 -type d -mtime +${DAYS_TO_KEEP} -print0 | xargs -r -0 rm -rf

/usr/bin/ydcmd --rsync --quiet put "${LOCAL_PATH}/" "${REMOTE_PATH}/"
