#!/usr/bin/env python
# -*- coding: utf-8 -*-

__title__    = "ydcmd"
__version__  = "0.1"
__author__   = "Anton Batenev"
__license__  = "BSD"


import array, os, sys, time
import socket, ssl
import urllib, httplib, urllib2
import string, re, json
import hashlib, shutil, ConfigParser
import email.utils


class ydCertificateError(ValueError):
    """
    Исключение при проверке валидности SSL сертификата
    """
    pass


class _ydHTTPSConnection(httplib.HTTPSConnection):
    """
    Сабклассинг httplib.HTTPSConnection для:
        * Проверки валидности SSL сертификата
        * Установки предпочитаемого набора шифров / алгоритма шифрования
        * Задания размера отсылаемого блока

    Дополнительные аргументы:
        options (dict) -- Опции приложения
    """
    def __init__(self, host, **kwargs):
        self._options = kwargs.pop("options", None)
        httplib.HTTPSConnection.__init__(self, host, **kwargs)


    def _ydCheckCert(self, cert, hostname):
        """
        Проверка валидности SSL сертификата

        Аргументы:
            cert     (dict) -- Данные сертификата
            hostname (str)  -- Имя хоста

        Исключения:
            ydCertificateError в случае ошибки проверки валидности сертификата
            (подробнее см. https://gist.github.com/zed/1347055)
        """
        def _ydDNS(dn):
            pats = []
            for frag in dn.split(r"."):
                if frag == '*':
                    pats.append("[^.]+")
                else:
                    frag = re.escape(frag)
                    pats.append(frag.replace(r"\*", "[^.]*"))
            return re.compile(r"\A" + r"\.".join(pats) + r"\Z", re.IGNORECASE)


        if not cert:
            raise ValueError("Empty or no certificate")

        notafter = cert.get("notAfter", None)
        if notafter == None:
            raise ydCertificateError("No appropriate notAfter field were found in certificate")
        if time.mktime(email.utils.parsedate(notafter)) < time.time():
            raise ydCertificateError("Cirtificate expired at %s" % notafter)

        san      = cert.get("subjectAltName", ())
        dnsnames = []

        for key, value in san:
            if key == "DNS":
                if _ydDNS(value).match(hostname):
                    return
                dnsnames.append(value)

        if not dnsnames:
            for sub in cert.get("subject", ()):
                for key, value in sub:
                    if key == "commonName":
                        if _ydDNS(value).match(hostname):
                            return
                        dnsnames.append(value)

        if len(dnsnames) > 1:
            raise ydCertificateError("Certificate hostname %r doesn't match either of %s" % (hostname, ", ".join(map(repr, dnsnames))))
        elif len(dnsnames) == 1:
            raise ydCertificateError("Certificate hostname %r doesn't match %r" % (hostname, dnsnames[0]))
        else:
            raise ydCertificateError("No appropriate commonName or subjectAltName fields were found in certificate")


    def connect(self):
        """
        Перегрузка httplib.HTTPSConnection.connect для проверки валидности SSL сертификата
        и установки предпочитаемого набора шифров / алгоритма шифрования
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)

        if getattr(self, "_tunnel_host", None):
            self.sock = sock
            self._tunnel()

        kwargs   = {}
        ca_certs = self._options["ca-file"]
        if ca_certs != None:
            kwargs.update (
                cert_reqs = ssl.CERT_REQUIRED,
                ca_certs  = ca_certs
            )

        self.sock = ssl.wrap_socket(sock, keyfile = self.key_file, certfile = self.cert_file, ssl_version = ssl.PROTOCOL_TLSv1, ciphers = self._options["ciphers"], **kwargs)

        if self._options["debug"] == True:
            ciphers = self.sock.cipher()
            ydDebug("Connected to %s:%d (%s %s)" % (self.host, self.port, ciphers[1], ciphers[0]))

        if ca_certs != None:
            try:
                self._ydCheckCert(self.sock.getpeercert(), self.host)
            except ydCertificateError:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                raise


    def send(self, data):
        """
        Перегрузка httplib.HTTPConnection.send для возможности задания размера отсылаемого блока
        """
        if self.sock is None:
            if self.auto_open:
                self.connect()
            else:
                raise NotConnected()

        if hasattr(data, "read") and not isinstance(data, array.array):
            chunk = self._options["chunk"]
            datablock = data.read(chunk)
            while datablock:
                self.sock.sendall(datablock)
                datablock = data.read(chunk)
        else:
            self.sock.sendall(data)


class _ydHTTPSHandler(urllib2.HTTPSHandler):
    """
    Сабклассинг urllib2.HTTPSHandler для:
        * Проверки валидности SSL сертификата
        * Установки предпочитаемого набора шифров / алгоритма шифрования
        * Задания размера отсылаемого блока

    Аргументы:
        options (dict) -- Опции приложения
    """
    def __init__(self, options, debuglevel = 0):
        """
        Аргументы:
            options (dict) -- Опции приложения
        """
        self._options = options

        urllib2.HTTPSHandler.__init__(self, debuglevel)


    def https_open(self, req):
        """
        Перегрузка urllib2.HTTPSHandler.https_open для использования _ydHTTPSConnection
        """
        return self.do_open(self._ydGetConnection, req)


    def _ydGetConnection(self, host, **kwargs):
        """
        Callback создания _ydHTTPSConnection
        """
        d = { "options" : self._options }
        d.update(kwargs)

        return _ydHTTPSConnection(host, **d)


def ydDefaultConfig():
    """
    Получение конфигурации приложения по умолчанию

    Результат (dict):
        Конфигурация приложения по умолчанию, которая может быть перегружена в вызове ydLoadConfig
    """
    return {
        "timeout"  : "30",
        "poll"     : "1",
        "retries"  : "3",
        "delay"    : "30",
        "limit"    : "100",   # default is 20
        "chunk"    : "512",   # default mdadm chunk size and optimal read-ahead is 512KB
        "token"    : "",
        "quiet"    : "no",
        "verbose"  : "no",
        "debug"    : "no",
        "async"    : "no",
        "rsync"    : "no",
        "base-url" : "https://cloud-api.yandex.net/v1/disk",
        "ca-file"  : "",
        "ciphers"  : ssl._DEFAULT_CIPHERS
    }


def ydHeaders(token):
    """
    Получение HTTP заголовков по умолчанию

    Аргументы:
        token (str) -- OAuth токен

    Результат (dict):
        Заголовки по умолчанию для передачи в запросе к API
    """
    return {
        "Accept"        : "application/json",
        "User-Agent"    : "ydcmd/%s (%s)" % (__version__, "https://github.com/abbat/ydcmd"),
        "Authorization" : "OAuth %s" % token
    }


def ydBool(value):
    """
    Преобразование строкового значения к булевому

    Аргументы:
        value (str|bool) -- Строковое представление булева значения

    Результат (bool):
        Результат преобразования строкового значения к булеву - [true|yes|t|y|1] => True, иначе False
    """
    if type(value) is bool:
        return value

    value = string.lower(value).strip()

    if value == "true" or value == "yes" or value == "t" or value == "y" or value == "1":
        return True

    return False


def ydHuman(value):
    """
    Преобразование числа байт в человекочитаемый вид

    Аргументы:
        value (int) -- Значение в байтах

    Результат (str):
        Человекочитаемое значение с размерностью
    """
    if value < 1024:
        return "%d" % (value)
    elif value < 1024 * 1024:
        return "%dK" % (value / 1024)
    elif value < 1024 * 1024 * 1024:
        return "%dM" % (value / 1024 / 1024)
    elif value < 1024 * 1024 * 1024 * 1024:
        return "%dG" % (value / 1024 / 1024 / 1024)

    return "%dT" % (value / 1024 / 1024 / 1024 / 1024)


class ydError(RuntimeError):
    """
    Внутреннее исключение, выбрасываемое в случаях:
        * Таймаут запроса к API
        * Исчерпание количества попыток запроса к API
        * Неверные аргументы, переданные в командной строке
    """
    def __init__(self, errno, errmsg):
        """
        Аргументы:
            errno  (int) -- Код ошибки (аналог кода возврата)
            errmsg (str) -- Текст ошибки
        """
        self.errno  = errno
        self.errmsg = "%s" % errmsg


def ydVerbose(errmsg, verbose = True):
    """
    Вывод расширенной информации

    Аргументы:
        errmsg  (str)  -- Сообщение для вывода в stderr
        verbose (bool) -- Флаг, разрешающий вывод сообщения
    """
    if verbose == True:
        sys.stderr.write("%s\n" % errmsg)


def ydDebug(errmsg, debug = True):
    """
    Вывод отладочной информации

    Аргументы:
        errmsg (str)  -- Сообщение для вывода в stderr
        debug  (bool) -- Флаг, разрешающий вывод сообщения
    """
    if debug == True:
        sys.stderr.write("--> %s\n" % errmsg)


def ydPath(path):
    """
    Конвертация облачного пути в канонический

    Аргументы:
        path (str) -- Путь в хранилище

    Результат (str):
        Канонический путь вида disk:/path
    """
    if path.find("disk:") != 0:
        if path[0] != "/":
            path = "/%s" % path
        path = "disk:%s" % path

    return path


def ydMD5(options, filename):
    """
    Подсчет md5 хэша файла

    Аргументы:
        options  (dict) -- Опции приложения
        filename (str)  -- Имя файла

    Результат (str):
        MD5 хэш файла
    """
    ydDebug("MD5: " + filename, options["debug"])

    chunk = options["chunk"]
    with open(filename, "rb") as fd:
        hasher = hashlib.md5()
        while True:
            data = fd.read(chunk)
            if not data:
                break
            hasher.update(data)

        return hasher.hexdigest()


def ydEnsureLocal(options, path, type):
    """
    Метод проверки возможности создания локального объекта требуемого типа.
    Если объект уже существует и типы не совпадают, производится удаление объекта.
    Если требуемый тип является директорией, то в случае ее отсутствия производится ее создание.

    Аргументы:
        options (dict) -- Опции приложения
        path    (str)  -- Объект
        type    (str)  -- Тип объекта (file|dir)

    Результат (bool):
        True если объект нужного типа уже существует, иначе False
    """
    if not (type == "dir" or type == "file"):
        raise ValueError("Unsupported type: %s" % type)

    if os.path.exists(path) == True:
        if os.path.islink(path) == True:
            ydDebug("rm %s" % path, options["debug"])
            os.unlink(path)
            return False
        if type == "dir":
            if os.path.isdir(path) == True:
                return True
            elif os.path.isfile(path) == True:
                ydDebug("rm %s" % path, options["debug"])
                os.remove(path)
            else:
                raise ydError(1, "Unsupported filesystem object: %s" % path)
        elif type == "file":
            if os.path.isfile(path) == True:
                return True
            elif os.path.isdir(path) == True:
                ydDebug("rm -r %s" % path, options["debug"])
                shutil.rmtree(path)
            else:
                raise ydError(1, "Unsupported filesystem object: %s" % path)
    elif type == "dir":
        ydDebug("mkdir %s" % path, options["debug"])
        os.mkdir(path)
        return True

    return False


def ydQueryRetry(options, method, url, data, headers, filename = None):
    """
    Реализация одной попытки запроса к API

    Аргументы:
        options  (dict) -- Опции приложения
        method   (str)  -- Тип запроса (GET|PUT|DELETE)
        url      (str)  -- URL запроса
        data     (dict) -- Параметры запроса
        headers  (dict) -- Заголовки запроса
        filename (str)  -- Имя файла для отправки / получения

    Результат (dict):
        Результат вызова API, преобразованный из JSON

    Исключения:
        ydError            -- При возврате HTTP кода отличного от HTTP-200 (errno будет равен HTTP коду)
        ydCertificateError -- При ошибке проверки сертификата сервера
    """
    url += ("" if data == None else "?%s" % urllib.urlencode(data))

    if options["debug"] == True:
        ydDebug("%s %s" % (method, url))
        if filename != None:
            ydDebug("File: %s" % filename)

    # страховка
    if re.match('^https:\/\/[a-z0-9\.\-]+\.yandex\.(net|ru|com)(:443){,1}\/', url, re.IGNORECASE) == None:
        raise RuntimeError("Malformed URL %s" % url)

    if method == "GET":
        request = urllib2.Request(url, None, headers)
    elif method == "PUT":
        fd = None
        if filename != None:
            fd = open(filename, "rb")

        request = urllib2.Request(url, fd, headers)
        request.get_method = lambda: method
    elif method == "DELETE" or method == "POST":
        request = urllib2.Request(url, None, headers)
        request.get_method = lambda: method
    else:
        raise ValueError("Unknown method: %s" % method)

    try:
        opener = urllib2.build_opener(_ydHTTPSHandler(options))
        result = opener.open(request, timeout = options["timeout"])
        code   = result.getcode()
        respt  = result.info().gettype()

        if code == 204 or code == 201:
            return {}
        elif method == "GET" and filename != None:
            chunk = options["chunk"]
            with open(filename, "wb") as fd:
                while True:
                    part = result.read(chunk)
                    if not part:
                        break
                    fd.write(part)
            return {}
        else:
            return json.load(result)
    except urllib2.HTTPError as e:
        try:
            result = json.load(e)

            if description in result:
                errmsg = "HTTP-%d: %s" % (e.code, result["description"])
            else:
                errmsg = "HTTP-%d: %s" % (e.code, e.msg)
        except:
            errmsg = "HTTP-%d: %s" % (e.code, e.msg)

        raise ydError(e.code, errmsg)


def ydQuery(options, method, url, data, headers, filename = None):
    """
    Реализация нескольких попыток запроса к API (см. ydQueryRetry)
    """
    retry   = 0
    retries = options["retries"]

    while True:
        try:
            return ydQueryRetry(options, method, url, data, headers, filename)
        except (urllib2.URLError, ssl.SSLError) as e:
            retry += 1
            ydDebug("Retry %d/%d: %s" % (retry, retries, e), options["debug"])
            if retry >= retries:
                raise ydError(1, e)
            time.sleep(options["delay"])


def ydWait(options, link):
    """
    Ожидание завершения операции

    Аргументы:
        options (dict) -- Опции приложения
        link    (dict) -- Ответ API на запрос операции
    """
    if options["async"] == True or not ("href" in link and "method" in link):
        return

    url     = link["href"]
    method  = link["method"]
    headers = ydHeaders(options["token"])

    while True:
        time.sleep(options["poll"])

        result = ydQuery(options, method, url, None, headers)

        if "status" in result:
            status = result["status"]
            if status == "in-progress":
                continue
            elif status == "success":
                break
            else:
                raise RuntimeError("Unknown status: %s" % status)


def ydStat(options, path):
    """
    Получение метаинформации об объекте в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        path    (str)  -- Имя файла или директории в хранилище

    Результат (dict):
        Метаинформация об объекте в хранилище
    """
    headers = ydHeaders(options["token"])

    data = {
        "path"   : "/",
        "offset" : 0,
        "limit"  : 0
    }

    if len(path) > 0:
        data["path"] = path

    method = "GET"
    url    = options["base-url"] + "/resources"

    part = ydQuery(options, method, url, data, headers)

    if "_embedded" in part:
        del part["_embedded"]

    if not ("type" in part and "name" in part):
        raise RuntimeError("Incomplete response")

    return part


def ydStatCmd(options, args):
    """
    Вывод метаинформации об объекте в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        args    (dict) -- Аргументы командной строки
    """
    if len(args) > 1:
        raise ydError(1, "Too many arguments")

    path = "/"
    if len(args) > 0:
        path = args[0]

    result = ydStat(options, ydPath(path))

    for key, value in result.iteritems():
        print "%10s: %s" % (key, value)


def ydList(options, path):
    """
    Получение списка файлов и директорий в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        path    (str)  -- Объект хранилища

    Результат (dict):
        Список имен объектов и метаинформации о них {"имя": {метаинформация}}
    """
    result = {}

    headers = ydHeaders(options["token"])

    data = {
        "path"   : "/",
        "offset" : 0,
        "limit"  : options["limit"]
    }

    if len(path) > 0:
        data["path"] = path

    method = "GET"
    url    = options["base-url"] + "/resources"

    while True:
        part = ydQuery(options, method, url, data, headers)

        if "_embedded" in part:
            part = part["_embedded"]
        elif "type" in part and "name" in part:
            result[part["name"]] = part
            return result
        else:
            raise RuntimeError("Incomplete response")

        for item in part["items"]:
            if not ("type" in item and "name" in item):
                raise RuntimeError("Incomplete response")
            result[item["name"]] = item

        if len(part["items"]) == int(part["limit"]):
            data["offset"] += int(part["limit"])
        else:
            break

    return result


def ydListCmd(options, args):
    """
    Вывод списка файлов и директорий в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        args    (dict) -- Аргументы командной строки
    """
    if len(args) > 1:
        raise ydError(1, "Too many arguments")

    path = "/"
    if len(args) > 0:
        path = args[0]

    result = ydList(options, ydPath(path))

    fshort = "short" in options
    flong  = "long"  in options
    fhuman = "human" in options or (fshort == False and flong == False)

    for item in result.itervalues():
        if "size" not in item:
            item["size"] = "<dir>"
        elif fhuman == True:
            item["size"] = ydHuman(item["size"])

        if flong == True:
            print "%(created)s %(modified)26s %(size)11s %(name)s" % item
        elif fshort == True:
            print "%(name)s" % item
        else:
            print "%(size)5s  %(name)s" % item


def ydDelete(options, path):
    """
    Удаление объекта в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        path    (str)  -- Объект хранилища
    """
    ydVerbose("Delete: %s" % path, options["verbose"])

    headers = ydHeaders(options["token"])

    data = {
        "path"        : path,
        "permanently" : "true"
    }

    method = "DELETE"
    url    = options["base-url"] + "/resources"

    link = ydQuery(options, method, url, data, headers)

    ydWait(options, link)


def ydDeleteCmd(options, args):
    """
    Обработчик удаления объекта хранилище

    Аргументы:
        options (dict) -- Опции приложения
        args    (dict) -- Аргументы командной строки
    """
    if len(args) < 1:
         raise ydError(1, "File or directory not specified")

    for arg in args:
        ydDelete(options, ydPath(arg))


def ydEnsure(options, path, type, stat = None):
    """
    Метод проверки возможности создания объекта требуемого типа в хранилище.
    Если объект уже существует и типы не совпадают, производится удаление объекта.
    Если требуемый тип является директорией, то в случае ее отсутствия производится ее создание.

    Аргументы:
        options (dict) -- Опции приложения
        path    (str)  -- Объект в хранилище
        type    (str)  -- Тип объекта в хранилище (file|dir)
        stat    (dict) -- Информация об объекте (если уже имеется)
    """
    if not (type == "dir" or type == "file"):
        raise ValueError("Unsupported type: %s", type)

    if stat == None:
        try:
            stat = ydStat(options, path)
        except ydError as e:
            if e.errno != 404:
                raise

    if stat != None:
        if not (stat["type"] == "dir" or stat["type"] == "file"):
            raise RuntimeError("Unsupported type: %s" % stat["type"])

        if stat["type"] != type:
            ydDelete(options, path)
            if type == "dir":
                ydCreate(options, path)
    elif type == "dir":
        ydCreate(options, path)


def ydCopy(options, source, target):
    """
    Копирование объекта в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        source  (str)  -- Исходный объект хранилища
        target  (str)  -- Конечный объект хранилища
    """
    ydVerbose("Copy: %s -> %s" % (source, target), options["verbose"])

    headers = ydHeaders(options["token"])

    data = {
        "from"      : source,
        "path"      : target,
        "overwrite" : "true"
    }

    method = "POST"
    url    = options["base-url"] + "/resources/copy"

    link = ydQuery(options, method, url, data, headers)

    ydWait(options, link)


def ydCopyCmd(options, args):
    """
    Обработчик копироавния объекта в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        args    (dict) -- Аргументы командной строки
    """
    if len(args) < 2:
        raise ydError(1, "Source or target not specified")
    if len(args) > 2:
        raise ydError(1, "Too many arguments")

    source = args[0]
    target = args[1]

    ydCopy(options, ydPath(source), ydPath(target))


def ydMove(options, source, target):
    """
    Перемещение объекта в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        source  (str)  -- Исходный объект хранилища
        target  (str)  -- Конечный объект хранилища
    """
    ydVerbose("Move: %s -> %s" % (source, target), options["verbose"])

    headers = ydHeaders(options["token"])

    data = {
        "from"      : source,
        "path"      : target,
        "overwrite" : "true"
    }

    method = "POST"
    url    = options["base-url"] + "/resources/move"

    link = ydQuery(options, method, url, data, headers)

    ydWait(options, link)


def ydMoveCmd(options, args):
    """
    Обработчик перемещения объекта в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        args    (dict) -- Аргументы командной строки
    """
    if len(args) < 2:
        raise ydError(1, "Source or target not specified")
    if len(args) > 2:
        raise ydError(1, "Too many arguments")

    source = args[0]
    target = args[1]

    ydMove(options, ydPath(source), ydPath(target))


def ydCreate(options, path):
    """
    Cоздание директории в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        path    (str)  -- Имя директории в хранилище
    """
    ydVerbose("Create: %s" % path, options["verbose"])

    headers = ydHeaders(options["token"])

    data = {
        "path" : path
    }

    method = "PUT"
    url    = options["base-url"] + "/resources"

    ydQuery(options, method, url, data, headers)


def ydCreateCmd(options, args):
    """
    Обработчик создания директории в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        args    (dict) -- Аргументы командной строки
    """
    if len(args) < 1:
        raise ydError(1, "Directory name not specified")

    for arg in args:
        ydCreate(options, ydPath(arg))


def ydPutRetry(options, source, target):
    """
    Реализация одной попытки помещения файла в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        source  (str)  -- Имя локального файла
        target  (str)  -- Имя файла в хранилище
    """
    headers = ydHeaders(options["token"])

    data = {
        "path"      : target,
        "overwrite" : "true"
    }

    method = "GET"
    url    = options["base-url"] + "/resources/upload"

    result = ydQueryRetry(options, method, url, data, headers)

    if "href" in result and "method" in result:
        url    = result["href"]
        method = result["method"]

        headers["Content-Type"]   = "application/octet-stream"
        headers["Content-Length"] = os.path.getsize(source)

        ydQueryRetry(options, method, url, None, headers, source)
    else:
        raise RuntimeError("Incomplete response")


def ydPut(options, source, target):
    """
    Реализация нескольких попыток загрузки файла в хранилище (см. ydPutRetry)
    """
    ydVerbose("Transfer: %s -> %s" % (source, target), options["verbose"])

    retry   = 0
    retries = options["retries"]

    while True:
        try:
            ydPutRetry(options, source, target)
            break
        except (urllib2.URLError, ssl.SSLError) as e:
            retry += 1
            ydDebug("Retry %d/%d: %s" % (retry, retries, e), options["debug"])
            if retry >= retries:
                raise ydError(1, e)
            time.sleep(options["delay"])


def ydPutSync(options, source, target):
    """
    Синхронизация локальных файлов и директорий с находящимися в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        source  (str)  -- Имя локальной директории (со слешем)
        target  (str)  -- Имя директории в хранилище (со слешем)
    """
    flist = ydList(options, target)

    for item in os.listdir(source):
        sitem = source + item
        titem = target + item

        if os.path.islink(sitem) == False:
            if os.path.isdir(sitem) == True:
                ydEnsure(options, titem, "dir", flist[item])
                ydPutSync(options, sitem + "/", titem + "/")
            elif os.path.isfile(sitem):
                force = True
                if item in flist:
                    ydEnsure(options, titem, "file", flist[item])
                    if flist[item]["type"] == "file" and os.path.getsize(sitem) == flist[item]["size"] and ydMD5(options, sitem) == flist[item]["md5"]:
                        force = False

                if force == True:
                    ydPut(options, sitem, titem)
            else:
                raise ydError(1, "Unsupported filesystem object: %s" % sitem)

            if item in flist:
                del flist[item]
        else:
            ydVerbose("Skip: %s" % sitem, options["verbose"])

    if options["rsync"] == True:
        for item in flist.itervalues():
            ydDelete(options, target + item["name"])


def ydPutCmd(options, args):
    """
    Обработчик загрузки файла в хранилище

    Аргументы:
        options (dict) -- Опции приложения
        args    (dict) -- Аргументы командной строки
    """
    if len(args) < 1:
        raise ydError(1, "Source not specified")
    if len(args) > 2:
        raise ydError(1, "Too many arguments")

    source = args[0]

    if len(args) == 2:
        target = args[1]
    else:
        target = "/"

    if os.path.basename(target) == "":
        target += os.path.basename(source)

    if os.path.islink(source) == False:
        target = ydPath(target)
        if os.path.isdir(source):
            if os.path.basename(source) != "":
                source += "/"
            if os.path.basename(target) != "":
                target += "/"
            ydEnsure(options, target, "dir")
            ydPutSync(options, source, target)
        elif os.path.isfile(source) == True:
            ydEnsure(options, target, "file")
            ydPut(options, source, target)
        else:
            raise ydError(1, "Unsupported filesystem object: %s" % source)
    else:
        ydVerbose("Skip: %s" % source, options["verbose"])


def ydGetRetry(options, source, target):
    """
    Реализация одной попытки получения файла из хранилища

    Аргументы:
        options (dict) -- Опции приложения
        source  (str)  -- Имя файла в хранилище
        target  (str)  -- Имя локального файла
    """
    headers = ydHeaders(options["token"])

    data = {
        "path" : source
    }

    method = "GET"
    url    = options["base-url"] + "/resources/download"

    result = ydQueryRetry(options, method, url, data, headers)

    if "href" in result and "method" in result:
        url    = result["href"]
        method = result["method"]

        headers["Accept"] = "*/*"

        result = ydQueryRetry(options, method, url, None, headers, target)
    else:
        raise RuntimeError("Incomplete response")


def ydGet(options, source, target):
    """
    Реализация нескольких попыток получения файла из хранилища (см. ydGetRetry)
    """
    ydVerbose("Transfer: %s -> %s" % (source, target), options["verbose"])

    retry   = 0
    retries = options["retries"]

    while True:
        try:
            ydGetRetry(options, source, target)
            break
        except (urllib2.URLError, ssl.SSLError) as e:
            retry += 1
            ydDebug("Retry %d/%d: %s" % (retry, retries, e), options["debug"])
            if retry >= retries:
                raise ydError(1, e)
            time.sleep(options["delay"])


def ydGetSync(options, source, target):
    """
    Синхронизация файлов и директорий в хранилище с локальными

    Аргументы:
        options (dict) -- Опции приложения
        source  (str)  -- Имя директории в хранилище (со слешем)
        target  (str)  -- Имя локальной директории (со слешем)
    """
    flist = ydList(options, source)

    for item in flist.itervalues():
        sitem = source + item["name"]
        titem = target + item["name"]

        if item["type"] == "dir":
            ydEnsureLocal(options, titem, "dir")
            ydGetSync(options, sitem + "/", titem + "/")
        elif item["type"] == "file":
            force  = True
            exists = ydEnsureLocal(options, titem, "file")
            if exists == True and os.path.getsize(titem) == item["size"] and ydMD5(options, titem) == item["md5"]:
                force = False

            if force == True:
                ydGet(options, sitem, titem)
        else:
            raise ydError(1, "Unknown type: %s" % item["type"])

    if options["rsync"] == True:
        for item in os.listdir(target):
            if item not in flist:
                titem = target + item
                if os.path.islink(titem) == True:
                    ydDebug("rm %s" % titem, options["debug"])
                    os.remove(titem)
                elif os.path.isfile(titem) == True:
                    ydDebug("rm %s" % titem, options["debug"])
                    os.remove(titem)
                elif os.path.isdir(titem) == True:
                    ydDebug("rm -r %s" % titem, options["debug"])
                    shutil.rmtree(titem)
                else:
                    raise ydError(1, "Unsupported filesystem object: %s" % titem)


def ydGetCmd(options, args):
    """
    Обработчик получения файла из хранилища

    Аргументы:
        options (dict) -- Опции приложения
        args    (dict) -- Аргументы командной строки
    """
    if len(args) < 1:
        raise ydError(1, "Source not specified")
    if len(args) > 2:
        raise ydError(1, "Too many arguments")

    source = ydPath(args[0])

    if len(args) == 2:
        target = args[1]
    else:
        target = os.path.basename(source)

    stat = ydStat(options, source)

    if stat["type"] == "dir":
        if target == "":
            target = "."
        if os.path.basename(source) != "":
            source += "/"
        if os.path.basename(target) != "":
            target += "/"

        ydEnsureLocal(options, target, "dir")
        ydGetSync(options, source, target)
    elif stat["type"] == "file":
        force  = True
        exists = ydEnsureLocal(options, target, "file")
        if exists == True and os.path.getsize(target) == stat["size"] and ydMD5(options, target) == stat["md5"]:
            force = False
        if force == True:
            ydGet(options, source, target)
    else:
        raise RuntimeError("Incomplete response")


def _ydPrintUsage(cmd = None):
    """
    Вывод справки об использовании приложения и завершение работы

    Аргументы:
        cmd (str) -- Имя команды для которой выводится справка (пустое значение для справки по командам)
    """
    default = ydDefaultConfig()
    if cmd == None:
        print "Usage:"
        print "     %s <command> [options] [args]" % sys.argv[0]
        print ""
        print "Commands:"
        print "     help  -- describe the usage of this program or its subcommands"
        print "     ls    -- list files and directories"
        print "     rm    -- remove file or directory"
        print "     cp    -- copy file or directory"
        print "     mv    -- move file or directory"
        print "     put   -- upload file to cloud"
        print "     get   -- download file from cloud"
        print "     mkdir -- create directory"
        print "     stat  -- show metainformation about cloud object"
        print ""
        print "Options:"
        print "     --timeout=<N> -- timeout for api requests in seconds (default: %s)" % default["timeout"]
        print "     --retries=<N> -- api call retries count (default: %s)" % default["retries"]
        print "     --delay=<N>   -- api call delay between retries in seconds (default: %s)" % default["delay"]
        print "     --token=<S>   -- oauth token (default: none)"
        print "     --quiet       -- suppress all errors (default: %s)" % default["quiet"]
        print "     --verbose     -- verbose output (default: %s)" % default["verbose"]
        print "     --debug       -- debug output (default: %s)" % default["debug"]
        print "     --chunk=<N>   -- chunk size in KB for io operations (default: %s)" % default["chunk"]
        print "     --ca-file=<S> -- file with trusted CAs (default: none)"
        print "     --ciphers=<S> -- ciphers sute (default: %s)" % default["ciphers"]
        print ""
    elif cmd == "ls":
        print "Usage:"
        print "     %s ls [options] [disk:/object]" % sys.argv[0]
        print ""
        print "Options:"
        print "     --human -- human-readable file size"
        print "     --short -- short format (names only)"
        print "     --long  -- long format (created, modified, size, name)"
        print "     --limit -- limit rows by one api call (default: %s)" % default["limit"]
        print ""
        print " * If target is not specified, target will be root '/' directory"
        print ""
    elif cmd == "rm":
        print "Usage:"
        print "     %s rm <disk:/object1> [disk:/object2] ..." % sys.argv[0]
        print ""
        print "Options:"
        print "     --async    -- do not wait (poll cheks) for completion (default: %s)" % default["async"]
        print "     --poll=<N> -- poll time interval in seconds for asynchronous operations (default: %s)" % default["poll"]
        print ""
    elif cmd == "cp":
        print "Usage:"
        print "     %s cp <disk:/object1> <disk:/object2>" % sys.argv[0]
        print ""
        print "Options:"
        print "     --async    -- do not wait (poll cheks) for completion (default: %s)" % default["async"]
        print "     --poll=<N> -- poll time interval in seconds for asynchronous operations (default: %s)" % default["poll"]
        print ""
    elif cmd == "mv":
        print "Usage:"
        print "     %s mv <disk:/object1> <disk:/object2>" % sys.argv[0]
        print ""
        print "Options:"
        print "     --async    -- do not wait (poll cheks) for completion (default: %s)" % default["async"]
        print "     --poll=<N> -- poll time interval in seconds for asynchronous operations (default: %s)" % default["poll"]
        print ""
    elif cmd == "put":
        print "Usage:"
        print "     %s put <file> [disk:/object]" % sys.argv[0]
        print ""
        print "Options:"
        print "     --rsync -- sync remote tree with local"
        print ""
        print " * If target is not specified, target will be root '/' directory"
        print " * If target specify a directory (ended with '/'), source file name will be added"
        print " * If target file exists, it will be silently overwritten"
        print " * Symbolic links are ignored"
        print ""
    elif cmd == "get":
        print "Usage:"
        print "     %s get <disk:/object> [file]" % sys.argv[0]
        print ""
        print "Options:"
        print "     --rsync -- sync local tree with remote"
        print ""
        print " * If target is not specified, source file name will be used"
        print " * If target exists, it will be silently overwritten"
        print ""
    elif cmd == "mkdir":
        print "Usage:"
        print "     %s mkdir <disk:/path1> [disk:/path2] ..." % sys.argv[0]
        print ""
    elif cmd == "stat":
        print "Usage:"
        print "     %s stat [disk:/object]" % sys.argv[0]
        print ""
        print " * If target is not specified, target will be root '/' directory"
        print ""
    else:
        sys.stderr.write("Unknown command %s\n" % cmd)
        sys.exit(1)

    sys.exit(0)


def ydConfigOptions(config):
    """
    Преобразование конфигурации в опции приложения, передаваемые в качестве контекста

    Параметры:
        config (dict) -- Конфигурация приложения

    Результат (dict):
        Опции приложения
    """
    options = config.copy()

    options["timeout"]  = int(options["timeout"])
    options["poll"]     = int(options["poll"])
    options["limit"]    = int(options["limit"])
    options["retries"]  = int(options["retries"])
    options["delay"]    = int(options["delay"])
    options["chunk"]    = int(options["chunk"]) * 1024
    options["quiet"]    = ydBool(options["quiet"])
    options["debug"]    = ydBool(options["debug"]) and not options["quiet"]
    options["verbose"]  = (ydBool(options["verbose"]) or options["debug"]) and not options["quiet"]
    options["async"]    = ydBool(options["async"])
    options["rsync"]    = ydBool(options["rsync"])

    if options["ca-file"] == "":
        options["ca-file"] = None

    return options


def ydLoadConfig(filename, config = {}):
    """
    Чтение секции ydcmd INI файла ~/.ydcmd.cfg

    Аргументы:
        filename (str)  -- Имя INI файла
        config   (dict) -- Параметры по умолчанию

    Результат (dict):
        Параметры по умолчанию, добавленные/замененные параметрами из INI файла
    """
    config = config.copy()

    parser = ConfigParser.ConfigParser()
    parser.read(filename)

    for section in parser.sections():
        name = string.lower(section)
        if name == "ydcmd":
            for option in parser.options(section):
                config[string.lower(option)] = string.strip(parser.get(section, option))

    return config


if __name__ == "__main__":
    sys.argc = len(sys.argv)
    if sys.argc < 2:
        _ydPrintUsage()

    command = string.lower(sys.argv[1])
    if command == "help":
        command = None
        if sys.argc > 2:
            command = string.lower(sys.argv[2])
        _ydPrintUsage(command)

    handlers = {
        "ls"    : ydListCmd,
        "rm"    : ydDeleteCmd,
        "cp"    : ydCopyCmd,
        "mv"    : ydMoveCmd,
        "put"   : ydPutCmd,
        "get"   : ydGetCmd,
        "mkdir" : ydCreateCmd,
        "stat"  : ydStatCmd
    }

    if command not in handlers:
        _ydPrintUsage(command)

    options = ydLoadConfig(os.path.expanduser("~") + "/.ydcmd.cfg", ydDefaultConfig())

    args = []
    for i in xrange(2, sys.argc):
        arg = sys.argv[i]
        opt = re.split("^--(\S+?)(=(.*)){,1}$", arg)
        if len(opt) == 5:
            if opt[3] == None:
                opt[3] = True
            options[string.lower(opt[1])] = opt[3]
        else:
            args.append(arg)

    options = ydConfigOptions(options)

    if options["ca-file"] == None:
        ydVerbose("Unsafe HTTPS connection - ca-file not used", options["verbose"])

    try:
        handlers[command](options, args)
    except ydError as e:
        if options["quiet"] == False:
            sys.stderr.write("%s\n" % e.errmsg)
        sys.exit(e.errno)
    except ydCertificateError as e:
        if options["quiet"] == False:
            sys.stderr.write("%s\n" % e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)
