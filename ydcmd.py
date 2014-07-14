#!/usr/bin/env python
# -*- coding: utf-8 -*-

__title__    = "ydcmd"
__version__  = "0.1"
__author__   = "Anton Batenev"
__license__  = "BSD"


__all__ = ["ydError", "ydCertError", "ydConfig", "ydOptions", "ydBase", "ydExtended", "ydCmd"]


import array, os, sys
import socket, ssl
import urllib, httplib, urllib2
import string, re, json
import time, datetime
import hashlib, shutil, ConfigParser


try:
    import dateutil.parser
    import dateutil.relativedelta
except ImportError:
    err = "Python module dateutil not found.\nPlease, install \"%s\"\n"
    name = os.uname()[0]
    if name == "FreeBSD":
        sys.stderr.write(err % "devel/py-dateutil")
    elif name == "Linux":
        sys.stderr.write(err % "python-dateutil")
    sys.exit(1)


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


class ydCertError(ValueError):
    """
    Исключение при проверке валидности SSL сертификата
    """
    pass


class ydConfig(object):
    """
    Конфигурация приложения
    """
    @staticmethod
    def default_config():
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
            "ciphers"  : ssl._DEFAULT_CIPHERS,
            "depth"    : "1",
            "dry"      : "no",
            "type"     : "all",
            "keep"     : ""
        }


    @staticmethod
    def load_config(config = default_config.__func__(), filename = os.path.expanduser("~") + "/.ydcmd.cfg"):
        """
        Чтение секции ydcmd INI файла ~/.ydcmd.cfg

        Аргументы:
            config   (dict) -- Базовая конфигурация
            filename (str)  -- Имя INI файла
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


class ydOptions(object):

    """
    Опции приложения
    """
    def __init__(self, config = ydConfig.load_config()):
        """
        Аргументы:
            config (dict) -- конфигурация приложения
        """
        self.timeout  = int(config["timeout"])
        self.poll     = int(config["poll"])
        self.retries  = int(config["retries"])
        self.delay    = int(config["delay"])
        self.limit    = int(config["limit"])
        self.chunk    = int(config["chunk"]) * 1024
        self.token    = str(config["token"])
        self.quiet    = self._bool(config["quiet"])
        self.debug    = self._bool(config["debug"]) and not self.quiet
        self.verbose  = (self._bool(config["verbose"]) or self.debug) and not self.quiet
        self.async    = self._bool(config["async"])
        self.rsync    = self._bool(config["rsync"])
        self.baseurl  = str(config["base-url"])
        self.cafile   = str(config["ca-file"])
        self.ciphers  = str(config["ciphers"])

        if self.cafile == "":
            self.cafile = None

        self.depth = int(config["depth"])
        self.dry   = self._bool(config["dry"])
        self.type  = str(config["type"])
        self.keep  = str(config["keep"])

        self.short = True if "short" in config else None
        self.long  = True if "long"  in config else None
        self.human = True if "human" in config or (self.short == None and self.long == None) else None


    def __repr__(self):
        return "%s(%r)" % (self.__class__, self.__dict__)


    @staticmethod
    def _bool(value):
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


class ydItem(object):
    """
    Описатель элемента в хранилище
    """
    def __init__(self, info = None):
        """
        Аргументы:
            info (dict) -- Описатель элемента
        """
        common_attr = ["name", "created", "modified", "path", "type"]
        file_attr   = ["size", "mime_type", "md5"]

        for attr in common_attr:
            if attr not in info:
                raise ValueError("%s not exists (incomplete response?)" % attr)

        if info != None:
            for key, value in info.iteritems():
                self.__dict__[key] = value

        if self.type == "file":
            for attr in file_attr:
                if attr not in info:
                    raise ValueError("%s not exists (incomplete response?)" % attr)
        elif self.type == "dir":
            pass
        else:
            raise ValueError("Unknown item type: %s" % self.type)


    def isdir(self):
        return self.type == "dir"


    def isfile(self):
        return self.type == "file"


    def __str__(self):
        result = ""
        for key, value in self.__dict__.iteritems():
            result += "%10s: %s\n" % (key, value)
        return result


    def __repr__(self):
        return "%s(%r)" % (self.__class__, self.__dict__)


class ydBase(object):
    """
    Базовые методы работы с API
    """
    class _ydBaseHTTPSConnection(httplib.HTTPSConnection):
        """
        Сабклассинг httplib.HTTPSConnection для:
            * Проверки валидности SSL сертификата
            * Установки предпочитаемого набора шифров / алгоритма шифрования
            * Задания размера отсылаемого блока
        """
        def __init__(self, host, **kwargs):
            """
            Дополнительные аргументы:
                options (ydOptions) -- Опции приложения
            """
            self._options = kwargs.pop("options", None)
            httplib.HTTPSConnection.__init__(self, host, **kwargs)


        def _check_cert(self, cert, hostname):
            """
            Проверка валидности SSL сертификата

            Аргументы:
                cert     (dict) -- Данные сертификата
                hostname (str)  -- Имя хоста

            Исключения:
                ydCertError в случае ошибки проверки валидности сертификата
                (подробнее см. https://gist.github.com/zed/1347055)
            """
            def _dns(dn):
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
                raise ydCertError("No appropriate notAfter field were found in certificate")

            try:
                expire = dateutil.parser.parse(notafter).astimezone(dateutil.tz.tzutc())
            except:
                raise ydCertError("Can not parse cirtificate notAfter field")

            if expire < datetime.datetime.now(dateutil.tz.tzutc()).replace(microsecond = 0):
                raise ydCertError("Cirtificate expired at %s" % notafter)

            san      = cert.get("subjectAltName", ())
            dnsnames = []

            for key, value in san:
                if key == "DNS":
                    if _dns(value).match(hostname):
                        return
                    dnsnames.append(value)

            if not dnsnames:
                for sub in cert.get("subject", ()):
                    for key, value in sub:
                        if key == "commonName":
                            if _dns(value).match(hostname):
                                return
                            dnsnames.append(value)

            if len(dnsnames) > 1:
                raise ydCertError("Certificate hostname %r doesn't match either of %s" % (hostname, ", ".join(map(repr, dnsnames))))
            elif len(dnsnames) == 1:
                raise ydCertError("Certificate hostname %r doesn't match %r" % (hostname, dnsnames[0]))
            else:
                raise ydCertError("No appropriate commonName or subjectAltName fields were found in certificate")


        def connect(self):
            """
            Перегрузка httplib.HTTPSConnection.connect для проверки валидности SSL сертификата
            и установки предпочитаемого набора шифров / алгоритма шифрования
            """
            sock = socket.create_connection((self.host, self.port), self.timeout)

            if getattr(self, "_tunnel_host", None):
                self.sock = sock
                self._tunnel()

            kwargs = {}
            if self._options.cafile != None:
                kwargs.update (
                    cert_reqs = ssl.CERT_REQUIRED,
                    ca_certs  = self._options.cafile
                )

            self.sock = ssl.wrap_socket(sock, keyfile = self.key_file, certfile = self.cert_file, ssl_version = ssl.PROTOCOL_TLSv1, ciphers = self._options.ciphers, **kwargs)

            if self._options.debug == True:
                ciphers = self.sock.cipher()
                ydBase.debug("Connected to %s:%d (%s %s)" % (self.host, self.port, ciphers[1], ciphers[0]))

            if self._options.cafile != None:
                try:
                    self._check_cert(self.sock.getpeercert(), self.host)
                except ydCertError:
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
                datablock = data.read(self._options.chunk)
                while datablock:
                    self.sock.sendall(datablock)
                    datablock = data.read(self._options.chunk)
            else:
                self.sock.sendall(data)


    class _ydBaseHTTPSHandler(urllib2.HTTPSHandler):
        """
        Сабклассинг urllib2.HTTPSHandler для:
            * Проверки валидности SSL сертификата
            * Установки предпочитаемого набора шифров / алгоритма шифрования
            * Задания размера отсылаемого блока
        """
        def __init__(self, options, debuglevel = 0):
            """
            Аргументы:
                options (ydOptions) -- Опции приложения
            """
            self._options = options

            urllib2.HTTPSHandler.__init__(self, debuglevel)


        def https_open(self, req):
            """
            Перегрузка urllib2.HTTPSHandler.https_open для использования _ydBaseHTTPSConnection
            """
            return self.do_open(self._get_connection, req)


        def _get_connection(self, host, **kwargs):
            """
            Callback создания _ydBaseHTTPSConnection
            """
            d = { "options" : self._options }
            d.update(kwargs)

            return ydBase._ydBaseHTTPSConnection(host, **d)


    def __init__(self, options):
        """
        Аргументы:
            options (ydOptions) -- конфигурация приложения
        """
        self.options = options


    @staticmethod
    def verbose(errmsg, flag = True):
        """
        Вывод расширенной информации

        Аргументы:
            errmsg (str)  -- Сообщение для вывода в stderr
            flag   (bool) -- Флаг, разрешающий вывод сообщения
        """
        if flag == True:
            sys.stderr.write("%s\n" % errmsg)


    @staticmethod
    def debug(errmsg, flag = True):
        """
        Вывод отладочной информации

        Аргументы:
            errmsg (str)  -- Сообщение для вывода в stderr
            flag   (bool) -- Флаг, разрешающий вывод сообщения
        """
        if flag == True:
            sys.stderr.write("--> %s\n" % errmsg)


    def _headers(self):
        """
        Получение HTTP заголовков по умолчанию

        Результат (dict):
            Заголовки по умолчанию для передачи в запросе к API
        """
        return {
            "Accept"        : "application/json",
            "User-Agent"    : "ydcmd/%s (%s)" % (__version__, "https://github.com/abbat/ydcmd"),
            "Authorization" : "OAuth %s" % self.options.token
        }


    def query_retry(self, method, url, data, headers = None, filename = None):
        """
        Реализация одной попытки запроса к API

        Аргументы:
            method   (str)  -- Тип запроса (GET|PUT|DELETE)
            url      (str)  -- URL запроса
            data     (dict) -- Параметры запроса
            headers  (dict) -- Заголовки запроса
            filename (str)  -- Имя файла для отправки / получения

        Результат (dict):
            Результат вызова API, преобразованный из JSON

        Исключения:
            ydError            -- При возврате HTTP кода отличного от HTTP-200 (errno будет равен HTTP коду)
            ydCertError -- При ошибке проверки сертификата сервера
        """
        if headers == None:
            headers = self._headers()

        url += ("" if data == None else "?%s" % urllib.urlencode(data))

        if self.options.debug == True:
            self.debug("%s %s" % (method, url))
            if filename != None:
                self.debug("File: %s" % filename)

        # страховка
        if re.match('^https:\/\/[a-z0-9\.\-]+\.yandex\.(net|ru|com)(:443){,1}\/', url, re.IGNORECASE) == None:
            raise RuntimeError("Malformed URL %s" % url)

        if method not in ["GET", "POST", "PUT", "DELETE"]:
            raise ValueError("Unknown method: %s" % method)

        fd = None
        if filename != None and method == "PUT":
            fd = open(filename, "rb")

        request = urllib2.Request(url, fd, headers)
        request.get_method = lambda: method

        try:
            opener = urllib2.build_opener(ydBase._ydBaseHTTPSHandler(self.options))
            result = opener.open(request, timeout = self.options.timeout)
            code   = result.getcode()
            respt  = result.info().gettype()

            if code == 204 or code == 201:
                return {}
            elif method == "GET" and filename != None:
                with open(filename, "wb") as fd:
                    while True:
                        part = result.read(self.options.chunk)
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


    def query(self, method, url, data, headers = None, filename = None):
        """
        Реализация нескольких попыток запроса к API
        """
        retry = 0
        while True:
            try:
                return self.query_retry(method, url, data, headers, filename)
            except (urllib2.URLError, ssl.SSLError) as e:
                retry += 1
                self.debug("Retry %d/%d: %s" % (retry, self.options.retries, e), self.options.debug)
                if retry >= self.options.retries:
                    raise ydError(1, e)
                time.sleep(self.options.delay)


    def _wait(self, link):
        """
        Ожидание завершения операции

        Аргументы:
            link (dict) -- Ответ API на запрос операции
        """
        if self.options.async == True or not ("href" in link and "method" in link):
            return

        url    = link["href"]
        method = link["method"]

        while True:
            time.sleep(self.options.poll)

            result = self.query(method, url, None)

            if "status" in result:
                status = result["status"]
                if status == "in-progress":
                    continue
                elif status == "success":
                    break
                else:
                    raise RuntimeError("Unknown status: %s" % status)


    def stat(self, path):
        """
        Получение метаинформации об объекте в хранилище

        Аргументы:
            path (str) -- Имя файла или директории в хранилище

        Результат (ydItem):
            Метаинформация об объекте в хранилище
        """
        data = {
            "path"   : "/",
            "offset" : 0,
            "limit"  : 0
        }

        if len(path) > 0:
            data["path"] = path

        method = "GET"
        url    = self.options.baseurl + "/resources"

        part = self.query(method, url, data)

        if "_embedded" in part:
            del part["_embedded"]

        return ydItem(part)


    def list(self, path):
        """
        Получение списка файлов и директорий в хранилище

        Аргументы:
            path (str) -- Объект хранилища

        Результат (dict):
            Список имен объектов и метаинформации о них {"имя": ydItem}
        """
        result = {}

        data = {
            "path"   : "/",
            "offset" : 0,
            "limit"  : self.options.limit
        }

        if len(path) > 0:
            data["path"] = path

        method = "GET"
        url    = self.options.baseurl + "/resources"

        while True:
            part = self.query(method, url, data)

            if "_embedded" in part:
                part = part["_embedded"]
            else:
                item = ydItem(part)
                result[item.name] = item
                return result

            for item in part["items"]:
                item = ydItem(item)
                result[item.name] = item

            if len(part["items"]) == int(part["limit"]):
                data["offset"] += int(part["limit"])
            else:
                break

        return result


    def delete(self, path):
        """
        Удаление объекта в хранилище

        Аргументы:
            path (str) -- Объект хранилища
        """
        self.verbose("Delete: %s" % path, self.options.verbose)

        data = {
            "path"        : path,
            "permanently" : "true"
        }

        method = "DELETE"
        url    = self.options.baseurl + "/resources"

        link = self.query(method, url, data)

        self._wait(link)


    def copy(self, source, target):
        """
        Копирование объекта в хранилище

        Аргументы:
            source (str) -- Исходный объект хранилища
            target (str) -- Конечный объект хранилища
        """
        self.verbose("Copy: %s -> %s" % (source, target), self.options.verbose)

        data = {
            "from"      : source,
            "path"      : target,
            "overwrite" : "true"
        }

        method = "POST"
        url    = self.options.baseurl + "/resources/copy"

        link = self.query(method, url, data)

        self._wait(link)


    def move(self, source, target):
        """
        Перемещение объекта в хранилище

        Аргументы:
            source (str) -- Исходный объект хранилища
            target (str) -- Конечный объект хранилища
        """
        self.verbose("Move: %s -> %s" % (source, target), self.options.verbose)

        data = {
            "from"      : source,
            "path"      : target,
            "overwrite" : "true"
        }

        method = "POST"
        url    = self.options.baseurl + "/resources/move"

        link = self.query(method, url, data)

        self._wait(link)


    def create(self, path):
        """
        Cоздание директории в хранилище

        Аргументы:
            path (str) -- Имя директории в хранилище
        """
        self.verbose("Create: %s" % path, self.options.verbose)

        data = {
            "path" : path
        }

        method = "PUT"
        url    = self.options.baseurl + "/resources"

        self.query(method, url, data)


    def _put_retry(self, source, target):
        """
        Реализация одной попытки помещения файла в хранилище

        Аргументы:
            source (str) -- Имя локального файла
            target (str) -- Имя файла в хранилище
        """
        data = {
            "path"      : target,
            "overwrite" : "true"
        }

        method = "GET"
        url    = self.options.baseurl + "/resources/upload"

        result = self.query_retry(method, url, data)

        if "href" in result and "method" in result:
            url    = result["href"]
            method = result["method"]

            headers = self._headers()
            headers["Content-Type"]   = "application/octet-stream"
            headers["Content-Length"] = os.path.getsize(source)

            self.query_retry(method, url, None, headers, source)
        else:
            raise RuntimeError("Incomplete response")


    def put(self, source, target):
        """
        Реализация нескольких попыток загрузки файла в хранилище
        """
        self.verbose("Transfer: %s -> %s" % (source, target), self.options.verbose)

        retry = 0
        while True:
            try:
                self._put_retry(source, target)
                break
            except (urllib2.URLError, ssl.SSLError) as e:
                retry += 1
                self.debug("Retry %d/%d: %s" % (retry, self.options.retries, e), self.options.debug)
                if retry >= self.options.retries:
                    raise ydError(1, e)
                time.sleep(self.options.delay)


    def _get_retry(self, source, target):
        """
        Реализация одной попытки получения файла из хранилища

        Аргументы:
            source (str) -- Имя файла в хранилище
            target (str) -- Имя локального файла
        """
        data = {
            "path" : source
        }

        method = "GET"
        url    = self.options.baseurl + "/resources/download"

        result = self.query_retry(method, url, data)

        if "href" in result and "method" in result:
            url    = result["href"]
            method = result["method"]

            headers = self._headers()
            headers["Accept"] = "*/*"

            result = self.query_retry(method, url, None, headers, target)
        else:
            raise RuntimeError("Incomplete response")


    def get(self, source, target):
        """
        Реализация нескольких попыток получения файла из хранилища
        """
        self.verbose("Transfer: %s -> %s" % (source, target), self.options.verbose)

        retry = 0
        while True:
            try:
                self._get_retry(source, target)
                break
            except (urllib2.URLError, ssl.SSLError) as e:
                retry += 1
                self.debug("Retry %d/%d: %s" % (retry, self.options.retries, e), self.options.debug)
                if retry >= self.options.retries:
                    raise ydError(1, e)
                time.sleep(self.options.delay)


class ydExtended(ydBase):
    """
    Расширенные методы api
    """
    def __init__(self, options):
        """
        Аргументы:
            options (ydOptions) -- Опции приложения
        """
        ydBase.__init__(self, options)


    def md5(self, filename):
        """
        Подсчет md5 хэша файла

        Аргументы:
            filename (str) -- Имя файла

        Результат (str):
            MD5 хэш файла
        """
        self.debug("MD5: " + filename, self.options.debug)

        with open(filename, "rb") as fd:
            hasher = hashlib.md5()
            while True:
                data = fd.read(self.options.chunk)
                if not data:
                    break
                hasher.update(data)

            return hasher.hexdigest()


    def _ensure_remote(self, path, type, stat = None):
        """
        Метод проверки возможности создания объекта требуемого типа в хранилище.
        Если объект уже существует и типы не совпадают, производится удаление объекта.
        Если требуемый тип является директорией, то в случае ее отсутствия производится ее создание.

        Аргументы:
            path (str)    -- Объект в хранилище
            type (str)    -- Тип объекта в хранилище (file|dir)
            stat (ydItem) -- Информация об объекте (если уже имеется)
        """
        if not (type == "dir" or type == "file"):
            raise ValueError("Unsupported type: %s", type)

        if stat == None:
            try:
                stat = self.stat(path)
            except ydError as e:
                if e.errno != 404:
                    raise

        if stat != None:
            if stat.type != type:
                self.delete(path)
                if type == "dir":
                    self.create(path)
        elif type == "dir":
            self.create(path)


    def _put_sync(self, source, target):
        """
        Синхронизация локальных файлов и директорий с находящимися в хранилище

        Аргументы:
            source (str) -- Имя локальной директории (со слешем)
            target (str) -- Имя директории в хранилище (со слешем)
        """
        flist = self.list(target)

        for item in os.listdir(source):
            sitem = source + item
            titem = target + item

            if os.path.islink(sitem) == False:
                if os.path.isdir(sitem) == True:
                    self._ensure_remote(titem, "dir", flist[item])
                    self._put_sync(sitem + "/", titem + "/")
                elif os.path.isfile(sitem):
                    force = True
                    if item in flist:
                        self._ensure_remote(titem, "file", flist[item])
                        if flist[item].isfile() == True and os.path.getsize(sitem) == flist[item].size and self.md5(sitem) == flist[item].md5:
                            force = False

                    if force == True:
                        self.put(sitem, titem)
                else:
                    raise ydError(1, "Unsupported filesystem object: %s" % sitem)

                if item in flist:
                    del flist[item]
            else:
                self.verbose("Skip: %s" % sitem, self.options.verbose)

        if self.options.rsync == True:
            for item in flist.itervalues():
                self.delete(target + item.name)


    def _ensure_local(self, path, type):
        """
        Метод проверки возможности создания локального объекта требуемого типа.
        Если объект уже существует и типы не совпадают, производится удаление объекта.
        Если требуемый тип является директорией, то в случае ее отсутствия производится ее создание.

        Аргументы:
            path (str) -- Объект
            type (str) -- Тип объекта (file|dir)

        Результат (bool):
            True если объект нужного типа уже существует, иначе False
        """
        if not (type == "dir" or type == "file"):
            raise ValueError("Unsupported type: %s" % type)

        if os.path.exists(path) == True:
            if os.path.islink(path) == True:
                self.debug("rm %s" % path, self.options.debug)
                os.unlink(path)
                return False
            if type == "dir":
                if os.path.isdir(path) == True:
                    return True
                elif os.path.isfile(path) == True:
                    self.debug("rm %s" % path, self.options.debug)
                    os.remove(path)
                else:
                    raise ydError(1, "Unsupported filesystem object: %s" % path)
            elif type == "file":
                if os.path.isfile(path) == True:
                    return True
                elif os.path.isdir(path) == True:
                    self.debug("rm -r %s" % path, self.options.debug)
                    shutil.rmtree(path)
                else:
                    raise ydError(1, "Unsupported filesystem object: %s" % path)
        elif type == "dir":
            self.debug("mkdir %s" % path, self.options.debug)
            os.mkdir(path)
            return True

        return False


    def _get_sync(self, source, target):
        """
        Синхронизация файлов и директорий в хранилище с локальными

        Аргументы:
            source (str) -- Имя директории в хранилище (со слешем)
            target (str) -- Имя локальной директории (со слешем)
        """
        flist = self.list(source)

        for item in flist.itervalues():
            sitem = source + item["name"]
            titem = target + item["name"]

            if item.isdir() == True:
                self._ensure_local(titem, "dir")
                self._get_sync(sitem + "/", titem + "/")
            elif item.isfile() == True:
                force  = True
                exists = self._ensure_local(titem, "file")
                if exists == True and os.path.getsize(titem) == item.size and self.md5(titem) == item.md5:
                    force = False

                if force == True:
                    self.get(sitem, titem)

        if self.options.rsync == True:
            for item in os.listdir(target):
                if item not in flist:
                    titem = target + item
                    if os.path.islink(titem) == True:
                        self.debug("rm %s" % titem, self.options.debug)
                        os.remove(titem)
                    elif os.path.isfile(titem) == True:
                        self.debug("rm %s" % titem, self.options.debug)
                        os.remove(titem)
                    elif os.path.isdir(titem) == True:
                        self.debug("rm -r %s" % titem, self.options.debug)
                        shutil.rmtree(titem)
                    else:
                        raise ydError(1, "Unsupported filesystem object: %s" % titem)


    def du(self, path, depth = 0):
        """
        Подсчет занимаемого места

        Аргументы:
            path  (str) -- Путь
            depth (int) -- Текущая глубина обхода

        Результат (list):
            Список [(имя, размер)] объектов
        """
        size   = 0
        result = []

        list = self.list(path)

        for item in list.itervalues():
            if item.isfile() == True:
                size += item.size
            elif item.isdir() == True:
                sub   = self.du(path + item.name + "/", depth + 1)
                size += sub[-1][1]
                if depth < self.options.depth:
                    result.extend(sub)

        result.append([path, size])

        return result


    def clean(self, path):
        """
        Очистка файлов и директорий

        Аргументы:
            path (str) -- Путь
        """
        if self.options.keep == "" or self.options.type not in ["all", "file", "dir"]:
            return

        flist = self.list(path).values()

        if self.options.type != "all":
            tlist = []
            for item in flist:
                if item.type == self.options.type:
                    tlist.append(item)
            flist = tlist

        for item in flist:
            item.modified = dateutil.parser.parse(item.modified).astimezone(dateutil.tz.tzutc())

        flist.sort(key = lambda x: x.modified)

        if re.match("^[0-9]+$", self.options.keep, re.IGNORECASE) != None:
            self.verbose("Clean: <%s> keep last %s" % (self.options.type, self.options.keep), self.options.verbose)
            flist = flist[:-int(self.options.keep)]
        elif re.match("^[0-9]+[dwmy]$", self.options.keep, re.IGNORECASE):
            m = re.split("^([0-9]+)([dwmy])$", self.options.keep, re.IGNORECASE)
            if m != None and len(m) == 4:
                count    = int(m[1])
                interval = str(m[2])

                relative = None
                if interval == "d":
                    relative = dateutil.relativedelta.relativedelta(days = -count)
                elif interval == "w":
                    relative = dateutil.relativedelta.relativedelta(weeks = -count)
                elif interval == "m":
                    relative = dateutil.relativedelta.relativedelta(months = -count)
                elif interval == "y":
                    relative = dateutil.relativedelta.relativedelta(years = -count)

                relative = datetime.datetime.now(dateutil.tz.tzutc()).replace(microsecond = 0) + relative

                self.verbose("Clean: <%s> before %s" % (self.options.type, relative.isoformat()), self.options.verbose)

                tlist = []
                for item in flist:
                    if item.modified < relative:
                        tlist.append(item)

                flist = tlist
        elif len(self.options.keep) >= 10:   # YYYY-MM-DD
            relative =  dateutil.parser.parse(self.options.keep).astimezone(dateutil.tz.tzutc())

            self.verbose("Clean: <%s> before %s" % (self.options.type, relative.isoformat()), self.options.verbose)

            tlist = []
            for item in flist:
                if item.modified < relative:
                    tlist.append(item)

            flist = tlist
        else:
            return

        for item in flist:
            if self.options.dry == True:
                print "%25s %7s %s" % (item.modified.isoformat(), ("<%s>" % item.type), item.name)
            else:
                self.delete(path + item.name)


class ydCmd(ydExtended):
    """
    Обработчики команд
    """
    def __init__(self, options):
        """
        Аргументы:
            options (ydOptions) -- Опции приложения
        """
        ydExtended.__init__(self, options)


    @staticmethod
    def human(val):
        """
        Преобразование числа байт в человекочитаемый вид

        Аргументы:
            val (int) -- Значение в байтах

        Результат (str):
            Человекочитаемое значение с размерностью
        """
        if val < 1024:
            return "%d" % (val)
        elif val < 1024 * 1024:
            return "%dK" % (val / 1024)
        elif val < 1024 * 1024 * 1024:
            return "%dM" % (val / 1024 / 1024)
        elif val < 1024 * 1024 * 1024 * 1024:
            return "%dG" % (val / 1024 / 1024 / 1024)

        return "%dT" % (val / 1024 / 1024 / 1024 / 1024)


    @staticmethod
    def remote_path(path):
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


    def stat_cmd(self, args):
        """
        Вывод метаинформации об объекте в хранилище

        Аргументы:
            args (dict) -- Аргументы командной строки
        """
        if len(args) > 1:
            raise ydError(1, "Too many arguments")

        path = "/"
        if len(args) > 0:
            path = args[0]

        print self.stat(self.remote_path(path))


    def list_cmd(self, args):
        """
        Вывод списка файлов и директорий в хранилище

        Аргументы:
            args (dict) -- Аргументы командной строки
        """
        if len(args) > 1:
            raise ydError(1, "Too many arguments")

        path = "/"
        if len(args) > 0:
            path = args[0]

        result = self.list(self.remote_path(path))

        for item in result.itervalues():
            if item.isdir() == True:
                size = "<dir>"
            elif self.options.human == True:
                size = self.human(item.size)
            else:
                size = item.size

            if self.options.long == True:
                print "%s %26s %11s %s" % (item.created, item.modified, size, item.name)
            elif self.options.short == True:
                print "%s" % item.name
            else:
                print "%5s  %s" % (size, item.name)


    def delete_cmd(self, args):
        """
        Обработчик удаления объекта хранилище

        Аргументы:
            args (dict) -- Аргументы командной строки
        """
        if len(args) < 1:
             raise ydError(1, "File or directory not specified")

        for arg in args:
            self.delete(self.remote_path(arg))


    def copy_cmd(self, args):
        """
        Обработчик копироавния объекта в хранилище

        Аргументы:
            args (dict) -- Аргументы командной строки
        """
        if len(args) < 2:
            raise ydError(1, "Source or target not specified")
        if len(args) > 2:
            raise ydError(1, "Too many arguments")

        source = args[0]
        target = args[1]

        self.copy(self.remote_path(source), self.remote_path(target))


    def move_cmd(self, args):
        """
        Обработчик перемещения объекта в хранилище

        Аргументы:
            args (dict) -- Аргументы командной строки
        """
        if len(args) < 2:
            raise ydError(1, "Source or target not specified")
        if len(args) > 2:
            raise ydError(1, "Too many arguments")

        source = args[0]
        target = args[1]

        self.move(self.remote_path(source), self.remote_path(target))


    def create_cmd(self, args):
        """
        Обработчик создания директории в хранилище

        Аргументы:
            args (dict) -- Аргументы командной строки
        """
        if len(args) < 1:
            raise ydError(1, "Directory name not specified")

        for arg in args:
            self.create(self.remote_path(arg))


    def put_cmd(self, args):
        """
        Обработчик загрузки файла в хранилище

        Аргументы:
            args (dict) -- Аргументы командной строки
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
            target = self.remote_path(target)
            if os.path.isdir(source):
                if os.path.basename(source) != "":
                    source += "/"
                if os.path.basename(target) != "":
                    target += "/"
                self._ensure_remote(target, "dir")
                self._put_sync(source, target)
            elif os.path.isfile(source) == True:
                self._ensure_remote(target, "file")
                self.put(source, target)
            else:
                raise ydError(1, "Unsupported filesystem object: %s" % source)
        else:
            self.verbose("Skip: %s" % source, self.options.verbose)


    def get_cmd(self, args):
        """
        Обработчик получения файла из хранилища

        Аргументы:
            args (dict) -- Аргументы командной строки
        """
        if len(args) < 1:
            raise ydError(1, "Source not specified")
        if len(args) > 2:
            raise ydError(1, "Too many arguments")

        source = self.remote_path(args[0])

        if len(args) == 2:
            target = args[1]
        else:
            target = os.path.basename(source)

        stat = self.stat(source)

        if stat.isdir() == True:
            if target == "":
                target = "."
            if os.path.basename(source) != "":
                source += "/"
            if os.path.basename(target) != "":
                target += "/"

            self._ensure_local(target, "dir")
            self._get_sync(source, target)
        elif stat.isfile() == True:
            force  = True
            exists = self._ensure_local(target, "file")
            if exists == True and os.path.getsize(target) == stat.size and self.md5(target) == stat.md5:
                force = False
            if force == True:
                self.get(source, target)


    def du_cmd(self, args):
        """
        Обработчик оценки занимаемого места

        Аргументы:
            args (dict) -- Аргументы командной строки
        """
        if len(args) > 1:
            raise ydError(1, "Too many arguments")

        if len(args) == 1:
            path = args[0]
        else:
            path = "/"

        if os.path.basename(path) != "":
            path += "/"

        result = self.du(self.remote_path(path))

        for name, size in result:
            name = name[5:-1]
            if len(name) == 0:
                name = "/"
            if options.human == True:
                print "%5s  %s" % (self.human(size), name)
            else:
                print "%11s  %s" % (size, name)


    def clean_cmd(self, args):
        """
        Обработчик очистки файлов и директорий

        Аргументы:
            args (dict) -- Аргументы командной строки
        """
        if len(args) > 1:
            raise ydError(1, "Too many arguments")

        if len(args) == 1:
            path = args[0]
        else:
            path = "/"

        if os.path.basename(path) != "":
            path += "/"

        self.clean(path)


    @staticmethod
    def print_usage(cmd = None):
        """
        Вывод справки об использовании приложения и завершение работы

        Аргументы:
            cmd (str) -- Имя команды для которой выводится справка (пустое значение для справки по командам)
        """
        default = ydConfig.default_config()
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
            print "Special commands:"
            print "     du    -- estimate files space usage"
            print "     clean -- delete old files and/or directories"
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
            print "Special options:"
            print "     --async -- do not wait (poll cheks) for completion (default: %s)" % default["async"]
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
            print "     --poll=<N> -- poll time interval in seconds for asynchronous operations (default: %s)" % default["poll"]
            print ""
        elif cmd == "cp":
            print "Usage:"
            print "     %s cp <disk:/object1> <disk:/object2>" % sys.argv[0]
            print ""
            print "Options:"
            print "     --poll=<N> -- poll time interval in seconds for asynchronous operations (default: %s)" % default["poll"]
            print ""
        elif cmd == "mv":
            print "Usage:"
            print "     %s mv <disk:/object1> <disk:/object2>" % sys.argv[0]
            print ""
            print "Options:"
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
        elif cmd == "du":
            print "Usage:"
            print "     %s du [disk:/object]" % sys.argv[0]
            print ""
            print "Options:"
            print "     --depth=<N> -- show size if dir is N or fewer levels below target (default: %s)" % default["depth"]
            print "     --long      -- show sizes in bytes instead human-readable format"
            print ""
            print " * If target is not specified, target will be root '/' directory"
            print ""
        elif cmd == "clean":
            print "Usage:"
            print "     %s clean <options> [disk:/object]" % sys.argv[0]
            print ""
            print "Options:"
            print "     --dry      -- just print list of object to delete (default: %s)" % default["dry"]
            print "     --type=<S> -- type of objects - 'file', 'dir' or 'all' (default: %s)" % default["type"]
            print "     --keep=<S> -- keep criteria (default: none):"
            print "                   * date ('2014-02-12T12:19:05+04:00')"
            print "                   * relative interval ('7d', '4w', '1m', '1y')"
            print "                   * number of objects ('31')"
            print ""
            print " * If target is not specified, target will be root '/' directory"
            print " * Objects sorted and filtered by modified date (not created date)"
            print ""
        else:
            sys.stderr.write("Unknown command %s\n" % cmd)
            sys.exit(1)

        sys.exit(0)


if __name__ == "__main__":
    sys.argc = len(sys.argv)
    if sys.argc < 2:
        ydCmd.print_usage()

    config = ydConfig.load_config()

    args = []
    for i in xrange(1, sys.argc):
        arg = sys.argv[i]
        opt = re.split("^--(\S+?)(=(.*)){,1}$", arg)
        if len(opt) == 5:
            if opt[3] == None:
                opt[3] = True
            config[string.lower(opt[1])] = opt[3]
        else:
            args.append(arg)

    options = ydOptions(config)

    command = string.lower(args.pop(0))
    if command == "help":
        command = None
        if sys.argc > 2:
            command = string.lower(args.pop(0))
        ydCmd.print_usage(command)

    if options.cafile == None:
        ydBase.verbose("Unsafe HTTPS connection - ca-file not used", options.verbose)

    try:
        cmd = ydCmd(options)
        if command == "ls":
            cmd.list_cmd(args),
        elif command == "rm":
            cmd.delete_cmd(args),
        elif command == "cp":
            cmd.copy_cmd(args),
        elif command == "mv":
            cmd.move_cmd(args),
        elif command == "put":
            cmd.put_cmd(args),
        elif command == "get":
            cmd.get_cmd(args),
        elif command == "mkdir":
            cmd.create_cmd(args),
        elif command == "stat":
            cmd.stat_cmd(args)
        elif command == "du":
            cmd.du_cmd(args)
        elif command == "clean":
            cmd.clean_cmd(args)
        else:
            ydCmd.print_usage(command)
    except ydError as e:
        if options.quiet == False:
            sys.stderr.write("%s\n" % e.errmsg)
        sys.exit(e.errno)
    except ydCertError as e:
        if options.quiet == False:
            sys.stderr.write("%s\n" % e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)
