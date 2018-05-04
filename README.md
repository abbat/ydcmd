# ydcmd

[English](https://github.com/abbat/ydcmd/blob/master/README.en.md) | [Türk](https://github.com/abbat/ydcmd/blob/master/README.tr.md)

Консольный клиент Linux/FreeBSD для работы с облачным хранилищем [Яндекс.Диск](https://disk.yandex.ru/) посредством [REST API](http://api.yandex.ru/disk/api/concepts/about.xml).

## Загрузка / Установка

* [Debian, Ubuntu](http://software.opensuse.org/download.html?project=home:antonbatenev:ydcmd&package=ydcmd)
* [Fedora, openSUSE, CentOS](http://software.opensuse.org/download.html?project=home:antonbatenev:ydcmd&package=ydcmd)
* [Ubuntu PPA](https://launchpad.net/~abbat/+archive/ubuntu/ydcmd) - `ppa:abbat/ydcmd`
* [Arch](http://software.opensuse.org/download.html?project=home:antonbatenev:ydcmd&package=ydcmd), [Arch AUR](https://aur.archlinux.org/packages/ydcmd/) (см. так же [AUR Helpers](https://wiki.archlinux.org/index.php/AUR_Helpers_(Русский)))
* Из исходного кода:

```
$ git clone https://github.com/abbat/ydcmd.git
$ sudo cp ydcmd/ydcmd.py /usr/local/bin/ydcmd
```

## Как можно помочь

* Переведите этот документ или [man-страницу](https://github.com/abbat/ydcmd/blob/master/man/ydcmd.ru.1) на свой родной язык;
* Исправляйте ошибки в этом документе или man-странице для своего родного языка;
* Делитесь информацией со своими друзьями;
* Отправляйте PR если вы разработчик.

## Подготовка к работе

Для работы клиента необходимо получить OAuth токен. Для его получения используйте команду `ydcmd token`, или [зарегистрируйте приложение на Яндексе](https://oauth.yandex.ru/client/new):

* `Название` - `ydcmd` (может быть любым)
* `Права` - `Яндекс.Диск REST API`
* `Клиент для разработки` - установить флажок

После регистрации приложения скопируйте `id приложения` и перейдите по ссылке:

* `https://oauth.yandex.ru/authorize?response_type=token&client_id=<id_приложения>`

После разрешения доступа сервис перенаправит вас по ссылке вида:

* `https://oauth.yandex.ru/verification_code?dev=True#access_token=<токен>`

Значение "токен" и есть требуемое. Подробнее можно ознакомиться по ссылке [получение отладочного токена вручную](http://api.yandex.ru/oauth/doc/dg/tasks/get-oauth-token.xml).

## Работа

Вывод краткой справки в консоли можно получить запуском скрипта без параметров или с командой `help`. Общий формат вызова:

```
ydcmd [команда] [опции] [аргументы]
```

**Команды**:

* `help` - получение краткой справки по командам и опциям приложения;
* `ls` - получение списка файлов и директорий;
* `rm` - удаление файла или директории;
* `cp` - копирование файла или директории;
* `mv` - перемещение файла или директории;
* `put` - загрузка файла или директории в хранилище;
* `get` - получение файла или директории из хранилища;
* `cat` - вывод файла из хранилища в stdout;
* `mkdir` - создание директории;
* `stat` - получение метаинформации об объекте;
* `info` - получение метаинформации о хранилище;
* `last` - получение метаинформации о последних загруженных файлах;
* `share` - публикация объекта (получение прямой ссылки);
* `revoke` - закрытие доступа к опубликованному ранее объекту;
* `du` - оценка места, занимаемого файлами в хранилище;
* `clean` - очистка файлов и директорий;
* `restore` - восстановление файла или директории из корзины;
* `download` - загрузка файла из интернета в хранилище;
* `token` - получение oauth токена для работы приложения.

**Опции**:

* `--config=<S>` - имя файла конфигурации (если отличается от файла по умолчанию);
* `--timeout=<N>` - таймаут в секундах на установку сетевого соединения;
* `--retries=<N>` - количество попыток вызова метода api перед возвратом кода ошибки;
* `--delay=<N>` - таймаут между попытками вызова метода api в секундах;
* `--limit=<N>` - количество элементов, возвращаемое одним вызовом метода получения списка файлов и директорий;
* `--token=<S>` - oauth токен (в целях безопасности рекомендуется указывать в конфигурационном файле или через переменную окружения `YDCMD_TOKEN`);
* `--quiet` - подавление вывода об ошибках, результат успеха операции определяется по коду возврата;
* `--verbose` - вывод расширенной информации;
* `--debug` - вывод отладочной информации;
* `--chunk=<N>` - размер блока данных в КБ для операций ввода/вывода;
* `--ca-file=<S>` - имя файла с сертификатами доверенных центров сертификации (при пустом значении проверка валидности сертификата не производится);
* `--ciphers=<S>` - набор алгоритмов шифрования (см. [ciphers(1)](https://www.openssl.org/docs/apps/ciphers.html));
* `--version` - вывод версии и завершение работы.

### Получение списка файлов и директорий

```
ydcmd ls [опции] [disk:/объект]
```

**Опции**:

* `--human` - вывод размера файла в человеко-читаемом виде;
* `--short` - вывод списка файлов и директорий без дополнительной информации (одно имя в одну строку);
* `--long` - вывод расширенного списка (время создания, время модификации, размер, имя файла).

Если целевой объект не указан, то будет использоваться корневая директория хранилища.

### Удаление файла или директории

```
ydcmd rm <disk:/объект>
```

**Опции**:

* `--trash` - удаление в корзину;
* `--poll=<N>` - время в секундах между опросом состояния при выполнении асинхронной операции;
* `--async` - выполнение команды без ожидания завершения (`poll`) операции.

Файлы удаляются без возможности восстановления. Директории удаляются рекурсивно (включая вложенные файлы и директории).

### Копирование файла или директории

```
ydcmd cp <disk:/объект1> <disk:/объект2>
```

**Опции**:

* `--poll=<N>` - время в секундах между опросом состояния при выполнении асинхронных операций;
* `--async` - выполнение команды без ожидания завершения (`poll`) операции.

В случае совпадения имен, директории и файлы будут перезаписаны. Директории копируются рекурсивно (включая вложенные файлы и директории).

### Перемещение файла или директории

```
ydcmd mv <disk:/объект1> <disk:/объект2>
```

**Опции**:

* `--poll=<N>` - время в секундах между опросом состояния при выполнении асинхронных операций;
* `--async` - выполнение команды без ожидания завершения (`poll`) операции.

В случае совпадения имени, директории и файлы будут перезаписаны.

### Загрузка файла в хранилище

```
ydcmd put <файл> [disk:/объект]
```

**Опции**:

* `--rsync` - синхронизация дерева файлов и директорий в хранилище с локальным деревом;
* `--no-recursion` - не загружать содержимое вложенных директорий;
* `--no-recursion-tag=<S>` - не загружать содержимое вложенных директорий, для директорий содержащих файл;
* `--exclude-tag=<S>` - пропускать загрузку директорий, содержащих файл;
* `--skip-hash` - пропускать проверки целостности md5/sha256;
* `--threads=<N>` - количество рабочих процессов;
* `--iconv=<S>` - при необходимости пытаться восстанавливать имена файлов и директорий из указанной кодировки (например, `--iconv=cp1251`);
* `--progress` - выводить прогресс операции (рекомендуется установить модуль python-progressbar).

Если целевой объект не указан, то для загрузки файла будет использоваться корневая директория хранилища. Если целевой объект указывает на директорию (заканчивается на `/`), то к имени директории будет добавлено имя исходного файла. Если целевой объект существует, то он будет перезаписан без запроса подтверждения. Символические ссылки игнорируются.

### Получение файла из хранилища

```
ydcmd get <disk:/объект> [файл]
```

**Опции**:

* `--rsync` - синхронизация локального дерева файлов и директорий с деревом в хранилище;
* `--no-recursion` - не загружать содержимое вложенных директорий;
* `--skip-hash` - пропускать проверки целостности md5/sha256;
* `--threads=<N>` - количество рабочих процессов;
* `--progress` - выводить прогресс операции (рекомендуется установить модуль python-progressbar).

Если не указано имя целевого файла, будет использовано имя файла в хранилище. Если целевой объект существует, то он будет перезаписан без запроса подтверждения.

### Вывод файла из хранилища в stdout

```
ydcmd cat <disk:/объект>
```

### Создание директории

```
ydcmd mkdir <disk:/путь>
```

### Получение метаинформации об объекте

```
ydcmd stat [disk:/объект]
```

Если целевой объект не указан, то будет использоваться корневая директория хранилища.

### Получение метаинформации о хранилище

```
ydcmd info
```

**Опции**:

* `--long` - отображать размеры в байтах вместо человеко-читаемого вида.

### Получение метаинформации о последних загруженных файлах

```
ydcmd last [N]
```

**Опции**:

* `--human` - вывод размера файла в человеко-читаемом виде;
* `--short` - вывод списка файлов без дополнительной информации (одно имя в одну строку);
* `--long` - вывод расширенного списка (время создания, время модификации, размер, файл).

Если параметр N не задан, будет использовано значение по умолчанию из REST API.

### Публикация объекта

```
ydcmd share <disk:/объект>
```

Команда возвращает имя объекта в хранилище и ссылку на него.

### Закрытие доступа

```
ydcmd revoke <disk:/объект>
```

### Оценка занимаемого места

```
ydcmd du [disk:/объект]
```

**Опции**:

* `--depth=<N>` - отображать размеры директорий до уровня N;
* `--long` - отображать размеры в байтах вместо человеко-читаемого вида.

Если целевой объект не указан, то будет использоваться корневая директория хранилища.

### Очистка файлов и директорий

```
ydcmd clean <опции> [disk:/объект]
```

**Опции**:

* `--dry` - не выполнять удаление, а вывести список объектов для удаления;
* `--type=<S>` - тип объектов для удаления (`file` - файлы, `dir` - директории, `all` - все);
* `--keep=<S>` - критерий выборки объектов, которые требуется сохранить:
  * Для выбора даты **до** которой требуется удалить данные, можно использовать строку даты в формате ISO (например, `2014-02-12T12:19:05+04:00`);
  * Для выбора относительного времени, можно использовать число и размерность (например, `7d`, `4w`, `1m`, `1y`);
  * Для выбора количества копий, можно использовать число без размерности (например, `31`).

Если целевой объект не указан, то будет использоваться корневая директория хранилища. Сортировка и фильтрация объектов производится по дате модификации (не по дате создания).

### Восстановление файла или директории из корзины

```
ydcmd restore <trash:/объект> [имя]
```

**Опции**:

* `--poll=<N>` - время в секундах между опросом состояния при выполнении асинхронных операций;
* `--async` - выполнение команды без ожидания завершения (`poll`) операции.

В случае совпадения имен, директории и файлы будут перезаписаны. Директории восстанавливаются рекурсивно (включая вложенные файлы и директории).

### Загрузка файла из интернета в хранилище

```
ydcmd download <URL> [disk:/объект]
```

**Опции**:

* `--poll=<N>` - время в секундах между опросом состояния при выполнении асинхронных операций;
* `--async` - выполнение команды без ожидания завершения (`poll`) операции;
* `--no-redirects` - запрещение редиректов при загрузке.

Если целевой объект не указан, то будет использоваться корневая директория хранилища, а имя файла будет выбрано исходя из содержимого URL (если это возможно).

### Получение OAuth токена

```
ydcmd token [код]
```

Без указания аргумента команда выведет ссылку для получения кода. Откройте ссылку в браузере, разрешите доступ приложению и используйте полученный код как аргумент для получения OAuth токена.

## Конфигурация

Для удобства работы рекомендуется создать конфигурационный файл с именем `~/.ydcmd.cfg` и установить на него права `0600` или `0400`. Формат файла:

```
[ydcmd]
# комментарий
<option> = <value>
```

Например:

```
[ydcmd]
token   = 1234567890
verbose = yes
ca-file = /etc/ssl/certs/ca-certificates.crt
```

## Переменные окружения

* `YDCMD_TOKEN` - oauth токен, имеет приоритет перед опцией `--token`;
* `SSL_CERT_FILE` - имя файла с сертификатами доверенных центров сертификации, имеет приоритет перед опцией `ca-file`.

## Код выхода

При работе в автоматическом режиме (по cron) может быть полезно получить результат выполнения команды:

* `0` - успешное завершение;
* `1` - общая ошибка приложения;
* `4` - код состояния HTTP-4xx (ошибка клиента);
* `5` - код состояния HTTP-5xx (ошибка сервера).
