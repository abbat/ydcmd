#!/usr/bin/env python
# -*- coding: utf-8 -*-

__title__    = "ydcmd"
__version__  = "2.4"
__author__   = "Anton Batenev"
__license__  = "BSD"


import array, random
import os, sys, signal, errno
import socket, ssl
import re, codecs, json
import time, datetime
import multiprocessing.pool
import hashlib, shutil


try:
    import dateutil.parser
    import dateutil.relativedelta

    # Hide UnicodeWarning in dateutil under Windows
    # https://bugs.launchpad.net/dateutil/+bug/1227221
    if os.name == "nt":
        import warnings
        warnings.filterwarnings("ignore", category = UnicodeWarning)

except ImportError:
    sys.stderr.write("Python module dateutil not found.\nPlease, install \"python-dateutil\"\n")
    sys.exit(1)


# suggests
try:
    import progressbar as ydProgressBar
except:
    ydProgressBar = None


# PEP-8
try:
    import configparser
except ImportError:
    import ConfigParser as configparser


# PEP-469
try:
    dict.iteritems
except AttributeError:
    def itervalues(d):
        return iter(d.values())
    def iteritems(d):
        return iter(d.items())
    def listvalues(d):
        return list(d.values())
    def listitems(d):
        return list(d.items())
else:
    def itervalues(d):
        return d.itervalues()
    def iteritems(d):
        return d.iteritems()
    def listvalues(d):
        return d.values()
    def listitems(d):
        return d.items()


# PEP-3108
try:
    from http.client    import HTTPSConnection   as ydHTTPSConnectionBase
    from http.client    import NotConnected      as ydNotConnected
    from http.client    import BadStatusLine     as ydBadStatusLine
    from http.client    import CannotSendRequest as ydCannotSendRequest
    from urllib.request import HTTPSHandler      as ydHTTPSHandlerBase
    from urllib.request import Request           as ydRequest
    from urllib.request import build_opener      as yd_build_opener
    from urllib.error   import HTTPError         as ydHTTPError
    from urllib.error   import URLError          as ydURLError
    from urllib.parse   import urlencode         as yd_urlencode
except ImportError:
    from httplib        import HTTPSConnection   as ydHTTPSConnectionBase
    from httplib        import NotConnected      as ydNotConnected
    from httplib        import BadStatusLine     as ydBadStatusLine
    from httplib        import CannotSendRequest as ydCannotSendRequest
    from urllib2        import HTTPSHandler      as ydHTTPSHandlerBase
    from urllib2        import Request           as ydRequest
    from urllib2        import build_opener      as yd_build_opener
    from urllib2        import HTTPError         as ydHTTPError
    from urllib2        import URLError          as ydURLError
    from urllib         import urlencode         as yd_urlencode


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
        self.errmsg = "{0}".format(errmsg)

        # http://bugs.python.org/issue1692335
        self.args = (errno, errmsg)


    def __str__(self):
        return self.errmsg


class ydCertError(ValueError):
    """
    Исключение при проверке валидности SSL сертификата
    """
    pass


class ydHTTPSConnection(ydHTTPSConnectionBase):
    """
    Сабклассинг ydHTTPSConnectionBase для:
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
        ydHTTPSConnectionBase.__init__(self, host, **kwargs)


    @staticmethod
    def _check_cert(cert, hostname):
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
            raise ydCertError("Cirtificate expired at {0}".format(notafter))

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
            raise ydCertError("Certificate hostname {0!r} doesn't match either of {1!s}".format(hostname, ", ".join(map(repr, dnsnames))))
        elif len(dnsnames) == 1:
            raise ydCertError("Certificate hostname {0!r} doesn't match {1!r}".format(hostname, dnsnames[0]))
        else:
            raise ydCertError("No appropriate commonName or subjectAltName fields were found in certificate")


    def connect(self):
        """
        Перегрузка ydHTTPSConnectionBase.connect для проверки валидности SSL сертификата
        и установки предпочитаемого набора шифров / алгоритма шифрования
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if getattr(self, "_tunnel_host", None):
            self.sock = sock
            self._tunnel()

        kwargs = {}
        if self._options.cafile != None:
            kwargs.update (
                cert_reqs = ssl.CERT_REQUIRED,
                ca_certs  = self._options.cafile
            )

        if self._options.ciphers != None and yd_check_python23(7, 0, 2, 0):   # Python >= 2.7 / 3.2
            kwargs.update(ciphers = self._options.ciphers)

        sslv3_workaround = yd_check_python23(7, 9, 2, 0)   # Python >= 2.7.9 / 3.2
        if sslv3_workaround:
            kwargs.update(ssl_version = ssl.PROTOCOL_SSLv23)
        else:
            kwargs.update(ssl_version = ssl.PROTOCOL_TLSv1)

        self.sock = ssl.wrap_socket(sock, keyfile = self.key_file, certfile = self.cert_file, **kwargs)

        if sslv3_workaround:
            self.sock.context.options |= ssl.OP_NO_SSLv2
            self.sock.context.options |= ssl.OP_NO_SSLv3

        if self._options.debug:
            ciphers = self.sock.cipher()
            yd_debug("Connected to {0}:{1} ({2} {3})".format(self.host, self.port, self.sock.version() if yd_check_python23(7, 9, 5, 0) else ciphers[1], ciphers[0]))

        if self._options.cafile != None:
            try:
                self._check_cert(self.sock.getpeercert(), self.host)
            except ydCertError:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                raise


    def request(self, method, url, body = None, headers = {}):
        """
        Перегрузка ydHTTPSConnectionBase.request для сохранения Content-Length отправляемого файла
        """
        self._content_length = headers["Content-Length"] if "Content-Length" in headers else None
        self._send_request(method, url, body, headers)


    def upload(self, data):
        """
        Отправка данных в хранилище (вынесено из send)
        """
        if options.progress:
            written = 0
            start   = int(time.time())
            bar     = None

            try:
                total = int(self._content_length)
                if ydProgressBar:
                    try:
                        widgets = ["--> Upload: ", ydProgressBar.Percentage(), " ", ydProgressBar.Bar(left = "[", marker = "=", right = "]"), " ", ydProgressBar.ETA(), " ", ydProgressBar.FileTransferSpeed()]
                        bar = ydProgressBar.ProgressBar(widgets = widgets, maxval = total).start()
                    except:
                        total = yd_human(total)
                else:
                    total = yd_human(total)
            except:
                total = "-"

        datablock = data.read(self._options.chunk)

        while datablock:
            self.sock.sendall(datablock)

            if self._options.progress:
                written += len(datablock)
                if bar:
                    bar.update(written)
                else:
                    delta = int(time.time()) - start
                    if delta > 0:
                        sys.stderr.write("--> Upload: {0}/{1} ({2}/s){3}\r".format(yd_human(written), total, yd_human(written / delta), " " * 12))

            datablock = data.read(self._options.chunk)

        if self._options.progress:
            if bar:
                bar.finish()
            else:
                sys.stderr.write("{0}\r".format(" " * 33))


    def send(self, data):
        """
        Перегрузка ydHTTPSConnectionBase.send для возможности задания размера отсылаемого блока
        """
        if self.sock is None:
            if self.auto_open:
                self.connect()
            else:
                raise ydNotConnected()

        if hasattr(data, "read") and not isinstance(data, array.array):
            self.upload(data)
        else:
            self.sock.sendall(data)


class ydHTTPSHandler(ydHTTPSHandlerBase):
    """
    Сабклассинг ydHTTPSHandlerBase для:
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

        ydHTTPSHandlerBase.__init__(self, debuglevel)


    def https_open(self, req):
        """
        Перегрузка ydHTTPSHandlerBase.https_open для использования ydHTTPSConnection
        """
        return self.do_open(self._get_connection, req)


    def _get_connection(self, host, **kwargs):
        """
        Callback создания ydHTTPSConnection
        """
        d = { "options" : self._options }
        d.update(kwargs)

        return ydHTTPSConnection(host, **d)


class ydPool(multiprocessing.pool.Pool):
    """
    Сабклассинг multiprocessing.Pool для контроля списка результатов вызовов
    """
    def __init__(self, processes = None, initializer = None, initargs = ()):
        multiprocessing.pool.Pool.__init__(self, processes, initializer, initargs)
        self._apply_result_list = []


    def yd_apply_async(self, func, args = (), kwds = {}, callback = None):
        """
        Аналог multiprocessing.Pool.yd_apply_async с занесением результата
        во внутренний список для дальнейшего вызова yd_wait_async
        """
        result = self.apply_async(func, args, kwds, callback)
        self._apply_result_list.append(result)
        return result


    def yd_wait_async(self):
        """
        Получение результата всех вызовов yd_apply_async
        """
        for result in self._apply_result_list:
            result.get()
        self._apply_result_list = []


def yd_default_config():
    """
    Получение конфигурации приложения по умолчанию

    Результат (dict):
        Конфигурация приложения по умолчанию, которая может быть перегружена в вызове yd_load_config
    """
    result = {
        "timeout"          : "30",
        "poll"             : "1",
        "retries"          : "3",
        "delay"            : "30",
        "limit"            : "100",   # default is 20
        "chunk"            : "512",   # default mdadm chunk size and optimal read-ahead is 512KB
        "token"            : "",
        "quiet"            : "no",
        "verbose"          : "no",
        "debug"            : "no",
        "async"            : "no",
        "rsync"            : "no",
        "no-recursion"     : "no",
        "no-recursion-tag" : "",
        "exclude-tag"      : "",
        "skip-md5"         : "no",
        "threads"          : "0",
        "progress"         : "no",
        "iconv"            : "",
        "base-url"         : "https://cloud-api.yandex.net/v1/disk",
        "app-id"           : "2415aa2e6ceb4839b1202e15ac83536c",
        "app-secret"       : "b8ae32ce025c451f84bd7df17029cb55",
        "ca-file"          : "",
        "ciphers"          : "HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!SRP:!PSK:@STRENGTH",
        "depth"            : "1",
        "dry"              : "no",
        "type"             : "all",
        "keep"             : "",
        "trash"            : "no"
    }

    cafiles = [
        "/etc/ssl/certs/ca-certificates.crt",       # Debian, Ubuntu, Arch
        "/etc/pki/tls/certs/ca-bundle.trust.crt",   # CentOS, Fedora (EV certs)
        "/etc/ssl/ca-bundle.pem",                   # OpenSUSE
        "/usr/local/share/certs/ca-root-nss.crt"    # FreeBSD
    ]

    for cafile in cafiles:
        if os.path.isfile(cafile):
            result["ca-file"] = cafile
            break

    return result


def yd_load_config(filename, config = None):
    """
    Чтение секции ydcmd INI файла ~/.ydcmd.cfg

    Аргументы:
        filename (str)  -- Имя INI файла
        config   (dict) -- Базовая конфигурация

    Результат (dict):
        Конфигурация приложения на основе файла конфигурации
    """
    if config == None:
        config = yd_default_config()

    config = config.copy()

    parser = configparser.ConfigParser()
    parser.read(filename)

    for section in parser.sections():
        name = section.lower()
        if name == "ydcmd":
            for option in parser.options(section):
                config[option.lower()] = parser.get(section, option).strip()

    return config


class ydOptions(object):
    """
    Опции приложения
    """
    def __init__(self, config):
        """
        Аргументы:
            config (dict) -- конфигурация приложения
        """
        self.timeout          = int(config["timeout"])
        self.poll             = int(config["poll"])
        self.retries          = int(config["retries"])
        self.delay            = int(config["delay"])
        self.limit            = int(config["limit"])
        self.chunk            = int(config["chunk"]) * 1024
        self.token            = str(config["token"])
        self.quiet            = self._bool(config["quiet"])
        self.debug            = self._bool(config["debug"]) and not self.quiet
        self.verbose          = (self._bool(config["verbose"]) or self.debug) and not self.quiet
        self.async            = self._bool(config["async"])
        self.rsync            = self._bool(config["rsync"])
        self.recursion        = not self._bool(config["no-recursion"])
        self.no_recursion_tag = str(config["no-recursion-tag"])
        self.exclude_tag      = str(config["exclude-tag"])
        self.skip_md5         = self._bool(config["skip-md5"])
        self.threads          = int(config["threads"])
        self.progress         = self._bool(config["progress"]) and not self.quiet
        self.iconv            = str(config["iconv"])

        if self.iconv == "":
            self.iconv = None
        else:
            self.iconv = ["utf-8", self.iconv]

        self.baseurl   = str(config["base-url"])
        self.appid     = str(config["app-id"])
        self.appsecret = str(config["app-secret"])
        self.cafile    = str(config["ca-file"])
        self.ciphers   = str(config["ciphers"])

        if self.ciphers == "":
            self.ciphers = None

        if self.cafile == "":
            self.cafile = None

        self.depth = int(config["depth"])
        self.dry   = self._bool(config["dry"])
        self.type  = str(config["type"])
        self.keep  = str(config["keep"])
        self.trash = self._bool(config["trash"])

        self.short = True if "short" in config else None
        self.long  = True if "long"  in config else None
        self.human = True if "human" in config or (self.short == None and self.long == None) else None

        if "YDCMD_TOKEN" in os.environ:
            self.token = str(os.environ["YDCMD_TOKEN"])
        if "SSL_CERT_FILE" in os.environ:
            self.cafile = str(os.environ["SSL_CERT_FILE"])


    def __repr__(self):
        return "{0!s}({1!r})".format(self.__class__, self.__dict__)


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

        value = value.lower().strip()

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
        file_attr   = ["mime_type", "md5"]

        for attr in common_attr:
            if attr not in info:
                raise ValueError("{0} not exists (incomplete response?)".format(attr))

        if info != None:
            for key, value in iteritems(info):
                self.__dict__[key] = value

        if self.type == "file":
            for attr in file_attr:
                if attr not in info:
                    raise ValueError("{0} not exists (incomplete response?)".format(attr))
            if "size" not in info:
                self.__dict__["size"] = 0
        elif self.type == "dir":
            pass
        else:
            raise ValueError("Unknown item type: {0}".format(self.type))


    def isdir(self):
        return self.type == "dir"


    def isfile(self):
        return self.type == "file"


    def __str__(self):
        result = ""
        for key, value in iteritems(self.__dict__):
            result += "{0:>12}: {1}\n".format(key if key != "custom_properties" else "custom", value)
        return result


    def __repr__(self):
        return "{0!s}({1!r})".format(self.__class__, self.__dict__)


def yd_check_python23(py2minor, py2micro, py3minor, py3micro):
    """
    Проверка версии Python для обеспечения совместимости

    Аргументы:
        py2minor (int) -- minor версия для 2.x
        py2micro (int) -- micro версия для 2.x
        py3minor (int) -- minor версия для 3.x
        py3micro (int) -- micro версия для 3.x

    Результат (bool):
        Соответствие версии >= аргументам
    """
    return sys.version_info >= (2, py2minor, py2micro) if sys.version_info < (3, 0) else sys.version_info >= (3, py3minor, py3micro)


def yd_init_worker():
    """
    Callback для инициализации дочернего процесса при threads > 0
    Запрет прерывания по CTRL+C
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def yd_print(msg):
    """
    Вывод сообщения

    Аргументы:
        msg (str) -- Сообщение для вывода в stdout
    """
    sys.stdout.write("{0}\n".format(msg))


def yd_verbose(errmsg, flag = True):
    """
    Вывод расширенной информации

    Аргументы:
        errmsg (str)  -- Сообщение для вывода в stderr
        flag   (bool) -- Флаг, разрешающий вывод сообщения
    """
    if flag:
        sys.stderr.write("{0}\n".format(errmsg))


def yd_debug(errmsg, flag = True):
    """
    Вывод отладочной информации

    Аргументы:
        errmsg (str)  -- Сообщение для вывода в stderr
        flag   (bool) -- Флаг, разрешающий вывод сообщения
    """
    if flag:
        sys.stderr.write("--> {0}\n".format(errmsg))


def yd_human(val):
    """
    Преобразование числа байт в человекочитаемый вид

    Аргументы:
        val (int) -- Значение в байтах

    Результат (str):
        Человекочитаемое значение с размерностью
    """
    if val < 1024:
        return "{0}".format(val)
    elif val < 1024 * 1024:
        return "{0:.0f}".format(val / 1024) + "K"
    elif val < 1024 * 1024 * 1024:
        return "{0:.0f}".format(val / 1024 / 1024) + "M"
    elif val < 1024 * 1024 * 1024 * 1024:
        return "{0:.2f}".format(val / 1024.0 / 1024.0 / 1024.0).rstrip("0").rstrip(".") + "G"

    return "{0:.2f}".format(val / 1024.0 / 1024.0 / 1024.0 / 1024.0).rstrip("0").rstrip(".") + "T"


def yd_path_area(path):
    """
    Получение имени области в хранилище из пути

    Аргументы:
        path (str) -- Путь

    Результат:
        Имя области в хранилище или None, если область не определена
    """
    area = path.split(":", 2)
    if len(area) != 2:
        return None

    area = area[0]
    if area not in ["disk", "app", "trash"]:
        return None

    return area


def yd_remote_path(path, area = "disk"):
    """
    Конвертация неявного пути в путь от корня области в хранилище
    path/to, /path/to, area:/path/to -> area:/path/to

    Аргументы:
        path (str) -- Путь
        area (str) -- Область по умолчанию

    Результат (str):
        Путь от корня области в хранилище
    """
    if yd_path_area(path):
        return path

    if path[0] != "/":
        path = "/{0}".format(path)

    return "{0}:{1}".format(area, path)


def yd_headers(token):
    """
    Получение HTTP заголовков по умолчанию

    Аргументы:
        token (str) -- OAuth токен

    Результат (dict):
        Заголовки по умолчанию для передачи в запросе к API
    """
    return {
        "Accept"        : "application/json",
        "User-Agent"    : "ydcmd/{0}".format(__version__),
        "Authorization" : "OAuth {0}".format(token)
    }


def yd_query_download(options, response, filename):
    """
    Загрузка файла из хранилища

    Аргументы:
        options  (ydOptions)    -- Опции приложения
        response (HTTPResponse) -- HTTP ответ
        filename (str)          -- Имя локального файла для записи
    """
    if options.progress:
        read  = 0
        start = int(time.time())
        bar   = None

        try:
            total = int(response.info().get("Content-Length"))
            if ydProgressBar:
                try:
                    widgets = ["--> Download: ", ydProgressBar.Percentage(), " ", ydProgressBar.Bar(left = "[", marker = "=", right = "]"), " ", ydProgressBar.ETA(), " ", ydProgressBar.FileTransferSpeed()]
                    bar = ydProgressBar.ProgressBar(widgets = widgets, maxval = total).start()
                except:
                    total = yd_human(total)
            else:
                total = yd_human(total)
        except:
            total = "-"

    with open(filename, "wb") as fd:
        while True:
            part = response.read(options.chunk)
            if not part:
                break

            fd.write(part)

            if options.progress:
                read += len(part)
                if bar:
                    bar.update(read)
                else:
                    delta = int(time.time()) - start
                    if delta > 0:
                        sys.stderr.write("--> Download: {0}/{1} ({2}/s){3}\r".format(yd_human(read), total, yd_human(read / delta), " " * 12))

    if options.progress:
        if bar:
            bar.finish()
        else:
            sys.stderr.write("{0}\r".format(" " * 35))


def yd_query_retry(options, method, url, args, headers = None, filename = None, data = None):
    """
    Реализация одной попытки запроса к API

    Аргументы:
        options  (ydOptions) -- Опции приложения
        method   (str)       -- Тип запроса (GET|POST|PUT|DELETE)
        url      (str)       -- URL запроса
        args     (dict)      -- Параметры запроса
        headers  (dict)      -- Заголовки запроса
        filename (str)       -- Имя файла для отправки / получения
        data     (str)       -- Данные для тела POST запроса

    Результат (dict):
        Результат вызова API, преобразованный из JSON

    Исключения:
        ydError     -- При возврате HTTP кода отличного от HTTP-200 (errno будет равен HTTP коду)
        ydCertError -- При ошибке проверки сертификата сервера
    """
    if headers == None:
        headers = yd_headers(options.token)

    url += ("" if args == None else "?{0}".format(yd_urlencode(args)))

    if options.debug:
        yd_debug("{0} {1}".format(method, url))
        if filename != None:
            yd_debug("File: {0}".format(filename))

    # страховка
    if re.match('^https:\/\/[a-z0-9\.\-]+\.yandex\.(net|ru|com)(:443){,1}\/', url, re.IGNORECASE) == None:
        raise RuntimeError("Malformed URL {0}".format(url))

    if method not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
        raise ValueError("Unknown method: {0}".format(method))

    fd = None
    if method == "PUT" and filename != None:
        fd = open(filename, "rb")
    elif (method == "POST" or method == "PATCH") and data != None:
        fd = data.encode("utf-8")

    request = ydRequest(url, fd, headers)
    request.get_method = lambda: method

    try:
        opener = yd_build_opener(ydHTTPSHandler(options))
        result = opener.open(request, timeout = options.timeout)
        code   = result.getcode()

        if code == 204 or code == 201:
            return {}
        elif method == "GET" and filename != None:
            yd_query_download(options, result, filename)
            return {}
        else:
            def _json_convert(input):
                """
                Конвертер unicode строк в utf-8 при вызове json.load
                """
                if isinstance(input, dict):
                    return dict([(_json_convert(key), _json_convert(value)) for key, value in iteritems(input)])
                elif isinstance(input, list):
                    return [_json_convert(element) for element in input]
                elif isinstance(input, unicode):
                    return input.encode("utf-8")
                else:
                    return input

            if sys.version_info < (3, 0):
                return json.load(result, object_hook = _json_convert)
            else:
                return json.load(codecs.getreader("utf-8")(result))

    except ydHTTPError as e:
        try:
            result = json.load(e)

            if "description" in result:
                errmsg = "HTTP-{0}: {1}".format(e.code, result["description"])
            else:
                errmsg = "HTTP-{0}: {1}".format(e.code, e.msg)
        except:
            errmsg = "HTTP-{0}: {1}".format(e.code, e.msg)

        raise ydError(e.code, errmsg)


def yd_can_query_retry(e):
    """
    Проверка исключения при вызове yd_query_retry на возможность повторного запроса

    Аргументы:
        e (Exception) -- Исключение из yd_query_retry

    Результат:
        None или необработанное исключение
    """
    if type(e) == ydError and not (e.errno >= 500 or e.errno == 401 or e.errno == 429):
        raise e
    elif type(e) == socket.error and not (e.errno == errno.ECONNRESET or e.errno == errno.ECONNREFUSED):
        raise e


def yd_query(options, method, url, args, headers = None, filename = None, data = None):
    """
    Реализация нескольких попыток запроса к API (yd_query_retry)
    """
    retry = 0
    while True:
        try:
            return yd_query_retry(options, method, url, args, headers, filename, data)
        except (ydURLError, ydBadStatusLine, ydCannotSendRequest, ssl.SSLError, socket.error, ydError) as e:
            yd_can_query_retry(e)
            retry += 1
            yd_debug("Retry {0}/{1}: {2}".format(retry, options.retries, e), options.debug)
            if retry >= options.retries:
                raise ydError(1, e)
            time.sleep(options.delay)


def yd_wait(options, link):
    """
    Ожидание завершения операции

    Аргументы:
        options (ydOptions) -- Опции приложения
        link    (dict)      -- Ответ API на запрос операции
    """
    if options.async or not ("href" in link and "method" in link):
        return

    url    = link["href"]
    method = link["method"]

    while True:
        time.sleep(options.poll)

        result = yd_query(options, method, url, None)

        if "status" in result:
            status = result["status"]
            if status == "in-progress":
                continue
            elif status == "success":
                break
            else:
                raise RuntimeError("Unknown status: {0}".format(status))


def yd_info(options):
    """
    Получение метаинформации о хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения

    Результат (dict):
        Метаинформация о хранилище
    """
    method = "GET"
    url    = options.baseurl + "/"

    return yd_query(options, method, url, None)


def yd_stat(options, path, silent = False):
    """
    Получение метаинформации об объекте в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Имя файла или директории в хранилище
        silent  (bool)      -- Подавление HTTP-404 и возврат None

    Результат (ydItem):
        Метаинформация об объекте в хранилище
    """
    args = {
        "path"   : path,
        "offset" : 0,
        "limit"  : 0
    }

    method = "GET"
    url    = options.baseurl + ("/trash" if yd_path_area(path) == "trash" else "") + "/resources"

    try:
        part = yd_query(options, method, url, args)

        if "_embedded" in part:
            del part["_embedded"]

        return ydItem(part)
    except ydError as e:
        if silent and e.errno == 404:
            return None
        raise e


def yd_patch(options, path, info):
    """
    Добавление метаинформации объекту в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Имя файла или директории в хранилище
        info    (dict)      -- Метаинформация (без custom_properties)
    """
    yd_verbose("Patch: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method  = "PATCH"
    url     = options.baseurl + "/resources"
    data    = "{\"custom_properties\": " + json.dumps(info, ensure_ascii = False) + "}"
    headers = yd_headers(options.token)

    headers["Content-Length"] = len(data)
    headers["Content-Type"]   = "application/json"

    yd_query(options, method, url, args, headers, None, data)


def yd_list(options, path):
    """
    Получение списка файлов и директорий в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Объект хранилища

    Результат (dict):
        Список имен объектов и метаинформации о них { "имя" : ydItem }
    """
    result = {}

    args = {
        "path"   : path,
        "offset" : 0,
        "limit"  : options.limit
    }

    method = "GET"
    url    = options.baseurl + ("/trash" if yd_path_area(path) == "trash" else "") + "/resources"

    while True:
        part = yd_query(options, method, url, args)

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
            args["offset"] += int(part["limit"])
        else:
            break

    return result


def yd_last(options, limit):
    """
    Получение списка последних загруженных файлов

    Аргументы:
        options (ydOptions) -- Опции приложения
        limit   (int)       -- Количество файлов в списке

    Результат (dict):
        Список имен объектов и метаинформации о них { "путь" : ydItem }
    """
    result = {}

    args = None

    if limit > 0:
        args = {
            "limit" : limit
        }

    method = "GET"
    url    = options.baseurl + "/resources/last-uploaded"

    part = yd_query(options, method, url, args)

    for item in part["items"]:
        item = ydItem(item)
        result[item.path] = item

    return result


def yd_delete(options, path, silent = False):
    """
    Удаление объекта в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Объект хранилища
        silent  (bool)      -- Игнорировать ошибку, если объект (уже/еще?) не существует
    """
    yd_verbose("Delete: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    if not options.trash:
        args["permanently"] = "true"

    method = "DELETE"
    url    = options.baseurl + ("/trash" if yd_path_area(path) == "trash" else "") + "/resources"

    try:
        link = yd_query(options, method, url, args)
        yd_wait(options, link)
    except ydError as e:
        if not (silent and e.errno == 404):
            raise e


def yd_copy(options, source, target):
    """
    Копирование объекта в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        source  (str)       -- Исходный объект хранилища
        target  (str)       -- Конечный объект хранилища
    """
    yd_verbose("Copy: {0} -> {1}".format(source, target), options.verbose)

    args = {
        "from"      : source,
        "path"      : target,
        "overwrite" : "true"
    }

    method = "POST"
    url    = options.baseurl + "/resources/copy"

    link = yd_query(options, method, url, args)

    yd_wait(options, link)


def yd_move(options, source, target):
    """
    Перемещение объекта в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        source  (str)       -- Исходный объект хранилища
        target  (str)       -- Конечный объект хранилища
    """
    yd_verbose("Move: {0} -> {1}".format(source, target), options.verbose)

    args = {
        "from"      : source,
        "path"      : target,
        "overwrite" : "true"
    }

    method = "POST"
    url    = options.baseurl + "/resources/move"

    link = yd_query(options, method, url, args)

    yd_wait(options, link)


def yd_create(options, path, silent = False):
    """
    Cоздание директории в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Имя директории в хранилище
        silent  (bool)      -- Игноририровать ошибку, если директория (уже/еще?) существует
    """
    yd_verbose("Create: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method = "PUT"
    url    = options.baseurl + "/resources"

    try:
        yd_query(options, method, url, args)
    except ydError as e:
        # HTTP-409: Specified path "..." points to existent directory.
        if not (silent and e.errno == 409 and "points to existent directory" in e.errmsg):
            raise e


def yd_publish(options, path):
    """
    Публикация объекта (объект становится доступен по прямой ссылке)

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Имя файла или директории в хранилище

    Результат (ydItem):
        Метаинформация об объекте в хранилище
    """
    yd_verbose("Publish: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method = "PUT"
    url    = options.baseurl + "/resources/publish"

    yd_query(options, method, url, args)

    return yd_stat(options, path)


def yd_unpublish(options, path):
    """
    Закрытие публичного доступа к объекту (объект становится недоступен по прямой ссылке)

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Имя файла или директории в хранилище
    """
    yd_verbose("Unpublish: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method = "PUT"
    url    = options.baseurl + "/resources/unpublish"

    yd_query(options, method, url, args)


def yd_restore(options, path, name = None):
    """
    Восстановление объекта из корзины

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Объект в корзине
        name    (str)       -- Новое имя восстанавливаемого ресурса
    """
    if name:
        yd_verbose("Restore: {0} as {1}".format(path, name), options.verbose)
    else:
        yd_verbose("Restore: {0}".format(path), options.verbose)

    args = {
        "path"      : path,
        "overwrite" : "true"
    }

    if name:
        args["name"] = name

    method = "PUT"
    url    = options.baseurl + "/trash/resources/restore"

    link = yd_query(options, method, url, args)

    yd_wait(options, link)


def yd_put_retry(options, source, target):
    """
    Реализация одной попытки помещения файла в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        source  (str)       -- Имя локального файла
        target  (str)       -- Имя файла в хранилище
    """
    args = {
        "path"      : target,
        "overwrite" : "true"
    }

    method = "GET"
    url    = options.baseurl + "/resources/upload"

    result = yd_query_retry(options, method, url, args)

    if "href" in result and "method" in result:
        url    = result["href"]
        method = result["method"]

        headers = yd_headers(options.token)
        headers["Content-Type"]   = "application/octet-stream"
        headers["Content-Length"] = os.path.getsize(source)

        yd_query_retry(options, method, url, None, headers, source)
    else:
        raise RuntimeError("Incomplete response")


def yd_put(options, source, target):
    """
    Реализация нескольких попыток загрузки файла в хранилище (yd_put_retry)
    """
    yd_verbose("Transfer: {0} -> {1}".format(source, target), options.verbose)

    retry = 0
    while True:
        try:
            yd_put_retry(options, source, target)
            break
        except (ydURLError, ydBadStatusLine, ydCannotSendRequest, ssl.SSLError, socket.error, ydError) as e:
            yd_can_query_retry(e)
            retry += 1
            yd_debug("Retry {0}/{1}: {2}".format(retry, options.retries, e), options.debug)
            if retry >= options.retries:
                raise ydError(1, e)
            time.sleep(options.delay)


def yd_get_retry(options, source, target):
    """
    Реализация одной попытки получения файла из хранилища

    Аргументы:
        options (ydOptions) -- Опции приложения
        source  (str)       -- Имя файла в хранилище
        target  (str)       -- Имя локального файла
    """
    args = {
        "path" : source
    }

    method = "GET"
    url    = options.baseurl + "/resources/download"

    result = yd_query_retry(options, method, url, args)

    if "href" in result and "method" in result:
        url    = result["href"]
        method = result["method"]

        headers = yd_headers(options.token)
        headers["Accept"] = "*/*"

        result = yd_query_retry(options, method, url, None, headers, target)
    else:
        raise RuntimeError("Incomplete response")


def yd_get(options, source, target):
    """
    Реализация нескольких попыток получения файла из хранилища (yd_get_retry)
    """
    yd_verbose("Transfer: {0} -> {1}".format(source, target), options.verbose)

    retry = 0
    while True:
        try:
            yd_get_retry(options, source, target)
            break
        except (ydURLError, ydBadStatusLine, ydCannotSendRequest, ssl.SSLError, socket.error, ydError) as e:
            yd_can_query_retry(e)
            retry += 1
            yd_debug("Retry {0}/{1}: {2}".format(retry, options.retries, e), options.debug)
            if retry >= options.retries:
                raise ydError(1, e)
            time.sleep(options.delay)


def yd_md5(options, filename):
    """
    Подсчет md5 хэша файла

    Аргументы:
        options  (ydOptions) -- Опции приложения
        filename (str)       -- Имя файла

    Результат (str):
        MD5 хэш файла
    """
    yd_debug("MD5: " + filename, options.debug)

    with open(filename, "rb") as fd:
        hasher = hashlib.md5()
        while True:
            data = fd.read(options.chunk)
            if not data:
                break
            hasher.update(data)

        return hasher.hexdigest()


def yd_check_hash(options, filename, md5):
    """
    Проверка хэша файла

    Аргументы:
        options  (ydOptions) -- Опции приложения
        filename (str)       -- Имя файла
        md5      (str)       -- Сравниваемное значение MD5

    Результат (bool):
        Результат сравнения хэша
    """
    if options.skip_md5 or yd_md5(options, filename) == md5:
        return True

    return False


def yd_ensure_remote(options, path, type, stat):
    """
    Метод проверки возможности создания объекта требуемого типа в хранилище.
    Если объект уже существует и типы не совпадают, производится удаление объекта.
    Если требуемый тип является директорией, то в случае ее отсутствия производится ее создание.

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Объект в хранилище
        type    (str)       -- Тип объекта в хранилище (file|dir)
        stat    (ydItem)    -- Информация об объекте (None если объект отсутствует)

    Результат (ydItem):
        Метаинформация об объекте, если он уже существует и его тип совпадает с аргументом type.
    """
    if not (type == "dir" or type == "file"):
        raise ValueError("Unsupported type: {}".format(type))

    if stat != None:
        if stat.type != type:
            yd_delete(options, path, True)
            if type == "dir":
                yd_create(options, path, True)
        else:
            return stat
    elif type == "dir":
        yd_create(options, path, True)

    return None


def yd_put_file(options, source, target, stat = None):
    """
    Загрузка файла в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        source  (str)       -- Имя локального файла
        target  (str)       -- Имя файла хранилище
        stat    (ydItem)    -- Описатель файла в хранилище (None, если файл отсутствует)
    """
    if stat:
        stat = yd_ensure_remote(options, target, "file", stat)
    if not (stat and stat.isfile() and os.path.getsize(source) == stat.size and yd_check_hash(options, source, stat.md5)):
        yd_put(options, source, target)


def yd_iconv(options, name):
    """
    Попытка преобразования имени файла или директории из кодировки отличной от utf-8

    Аргументы:
        options (ydOptions) -- Опции приложения
        source  (str)       -- Имя локальной директории
    """
    if not options.iconv:
        return name

    for encoding in options.iconv:
        try:
            return name.decode(encoding).encode("utf-8")
        except UnicodeDecodeError:
            pass

    return None


def yd_put_sync(options, source, target, pool = None):
    """
    Синхронизация локальных файлов и директорий с находящимися в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        source  (str)       -- Имя локальной директории (со слешем)
        target  (str)       -- Имя директории в хранилище (со слешем)
        pool    (ydPool)    -- Пул процессов
    """
    if options.exclude_tag and os.path.isfile(source + options.exclude_tag):
        return

    local_recursion = True
    if options.no_recursion_tag and os.path.isfile(source + options.no_recursion_tag):
        local_recursion = False

    flist = yd_list(options, target)

    lazy_put_sync = []

    for item in os.listdir(source):
        sitem = source + item

        item = yd_iconv(options, item)
        if not item:
            yd_verbose("Skip: {0}".format(sitem), options.verbose)
            continue

        titem = target + item

        if not os.path.islink(sitem):
            if os.path.isdir(sitem):
                if options.recursion and local_recursion:
                    lazy_put_sync.append([sitem + "/", titem + "/"])
                if pool:
                    pool.yd_apply_async(yd_ensure_remote, args = (options, titem, "dir", flist[item] if item in flist else None))
                else:
                    yd_ensure_remote(options, titem, "dir", flist[item] if item in flist else None)
            elif os.path.isfile(sitem):
                if pool:
                    pool.yd_apply_async(yd_put_file, args = (options, sitem, titem, flist[item] if item in flist else None))
                else:
                    yd_put_file(options, sitem, titem, flist[item] if item in flist else None)
            else:
                raise ydError(1, "Unsupported filesystem object: {0}".format(sitem))

            if item in flist:
                del flist[item]
        else:
            yd_verbose("Skip: {0}".format(sitem), options.verbose)

    if options.rsync:
        for item in itervalues(flist):
            if pool:
                pool.yd_apply_async(yd_delete, args = (options, target + item.name, True))
            else:
                yd_delete(options, target + item.name, True)

    if pool:
        pool.yd_wait_async()

    # при большом количестве директорий рандомизация позволяет продолжить
    # загрузку не обрабатывая заново ранее загруженные директории
    random.shuffle(lazy_put_sync)

    index = 0
    count = len(lazy_put_sync)

    for [sitem, titem] in lazy_put_sync:
        try:
            index += 1
            yd_verbose("Processing [{0}/{1}]: {2}".format(index, count, sitem), options.verbose)
            yd_put_sync(options, sitem, titem, pool)
        except OSError as e:
            # аналогично поведению rsync, которая не останавливается с ошибкой
            # при исчезновении файлов и директорий во время синхронизации
            if e.errno == errno.ENOENT:
                yd_verbose("Warning: {0}".format(e), options.verbose)
            else:
                raise e


def yd_ensure_local(options, path, type):
    """
    Метод проверки возможности создания локального объекта требуемого типа.
    Если объект уже существует и типы не совпадают, производится удаление объекта.
    Если требуемый тип является директорией, то в случае ее отсутствия производится ее создание.

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Объект
        type    (str)       -- Тип объекта (file|dir)

    Результат (bool):
        True если объект нужного типа уже существует, иначе False
    """
    if not (type == "dir" or type == "file"):
        raise ValueError("Unsupported type: {0}".format(type))

    if os.path.exists(path):
        if os.path.islink(path):
            yd_debug("rm {0}".format(path), options.debug)
            os.unlink(path)
            return False
        if type == "dir":
            if os.path.isdir(path):
                return True
            elif os.path.isfile(path):
                yd_debug("rm {0}".format(path), options.debug)
                os.remove(path)
            else:
                raise ydError(1, "Unsupported filesystem object: {0}".format(path))
        elif type == "file":
            if os.path.isfile(path):
                return True
            elif os.path.isdir(path):
                yd_debug("rm -r {0}".format(path), options.debug)
                shutil.rmtree(path)
            else:
                raise ydError(1, "Unsupported filesystem object: {0}".format(path))
    elif type == "dir":
        yd_debug("mkdir {0}".format(path), options.debug)
        os.mkdir(path)
        return True

    return False


def yd_get_file(options, source, target, stat):
    """
    Получение файла из хранилища

    Аргументы:
        options (ydOptions) -- Опции приложения
        source  (str)       -- Имя файла в хранилище
        target  (str)       -- Имя локального файла
        stat    (ydItem)    -- Описатель файла в хранилище
    """
    exists = yd_ensure_local(options, target, "file")
    if not exists or not (os.path.getsize(target) == stat.size and yd_check_hash(options, target, stat.md5)):
        yd_get(options, source, target)


def yd_get_sync(options, source, target, pool = None):
    """
    Синхронизация файлов и директорий в хранилище с локальными

    Аргументы:
        options (ydOptions) -- Опции приложения
        source  (str)       -- Имя директории в хранилище (со слешем)
        target  (str)       -- Имя локальной директории (со слешем)
        pool    (ydPool)    -- Пул процессов
    """
    flist = yd_list(options, source)

    lazy_get_sync = []

    for item in itervalues(flist):
        sitem = source + item.name
        titem = target + item.name

        if item.isdir():
            if options.recursion:
                lazy_get_sync.append([sitem + "/", titem + "/"])
            yd_ensure_local(options, titem, "dir")
        elif item.isfile():
            if pool:
                pool.yd_apply_async(yd_get_file, args = (options, sitem, titem, item))
            else:
                yd_get_file(options, sitem, titem, item)

    if options.rsync:
        for item in os.listdir(target):
            if item not in flist:
                titem = target + item
                if os.path.islink(titem):
                    yd_debug("rm {0}".format(titem), options.debug)
                    os.remove(titem)
                elif os.path.isfile(titem):
                    yd_debug("rm {0}".format(titem), options.debug)
                    os.remove(titem)
                elif os.path.isdir(titem):
                    yd_debug("rm -r {0}".format(titem), options.debug)
                    shutil.rmtree(titem)
                else:
                    raise ydError(1, "Unsupported filesystem object: {0}".format(titem))

    if pool:
        pool.yd_wait_async()

    # при большом количестве директорий рандомизация позволяет продолжить
    # загрузку не обрабатывая заново ранее загруженные директории
    random.shuffle(lazy_get_sync)

    index = 0
    count = len(lazy_get_sync)

    for [sitem, titem] in lazy_get_sync:
        try:
            index += 1
            yd_verbose("Processing [{0}/{1}]: {2}".format(index, count, sitem), options.verbose)
            yd_get_sync(options, sitem, titem, pool)
        except ydError as e:
            # аналогично поведению rsync, которая не останавливается с ошибкой
            # при исчезновении файлов и директорий во время синхронизации
            if e.errno == 404:
                yd_verbose("Warning: {0}".format(e), options.verbose)
            else:
                raise e


def yd_du(options, path, depth = 0):
    """
    Подсчет занимаемого места

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Путь
        depth   (int)       -- Текущая глубина обхода

    Результат (list):
        Список [(имя, размер)] объектов
    """
    size   = 0
    result = []

    items = yd_list(options, path)

    for item in itervalues(items):
        if item.isfile():
            size += item.size
        elif item.isdir():
            sub   = yd_du(options, path + item.name + "/", depth + 1)
            size += sub[-1][1]
            if depth < options.depth:
                result.extend(sub)

    result.append([path, size])

    return result


def yd_clean(options, path):
    """
    Очистка файлов и директорий

    Аргументы:
        options (ydOptions) -- Опции приложения
        path    (str)       -- Путь
    """
    if options.keep == "" or options.type not in ["all", "file", "dir"]:
        return

    flist = listvalues(yd_list(options, path))

    if options.type != "all":
        tlist = []
        for item in flist:
            if item.type == options.type:
                tlist.append(item)
        flist = tlist

    for item in flist:
        item.modified = dateutil.parser.parse(item.modified).astimezone(dateutil.tz.tzutc())

    flist.sort(key = lambda x: x.modified)

    if re.match("^[0-9]+$", options.keep, re.IGNORECASE) != None:
        yd_verbose("Clean: <{0}> keep last {1}".format(options.type, options.keep), options.verbose)
        flist = flist[:-int(options.keep)]
    elif re.match("^[0-9]+[dwmy]$", options.keep, re.IGNORECASE):
        m = re.split("^([0-9]+)([dwmy])$", options.keep, re.IGNORECASE)
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

            yd_verbose("Clean: <{0}> before {1}".format(options.type, relative.isoformat()), options.verbose)

            tlist = []
            for item in flist:
                if item.modified < relative:
                    tlist.append(item)

            flist = tlist
    elif len(options.keep) >= 10:   # YYYY-MM-DD
        relative =  dateutil.parser.parse(options.keep).astimezone(dateutil.tz.tzutc())

        yd_verbose("Clean: <{0}> before {1}".format(options.type, relative.isoformat()), options.verbose)

        tlist = []
        for item in flist:
            if item.modified < relative:
                tlist.append(item)

        flist = tlist
    else:
        return

    for item in flist:
        if options.dry:
            yd_print("{0:>25}  {1:>7}  {2}".format(item.modified.isoformat(), "<{0}>".format(item.type), item.name))
        else:
            yd_delete(options, path + item.name)


def yd_info_cmd(options, args):
    """
    Вывод метаинформации о хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) > 0:
        raise ydError(1, "Too many arguments")

    result = yd_info(options)

    result["free_space"]     = int(result["total_space"]) - int(result["used_space"])
    result["used_space_pct"] = int(result["used_space"]) * 100 / int(result["total_space"])

    if result["free_space"] < 0:
        result["free_space"] = 0
    if result["used_space_pct"] > 100:
        result["used_space_pct"] = 100

    if options.human:
        result["used_space"]  = yd_human(result["used_space"])
        result["free_space"]  = yd_human(result["free_space"])
        result["total_space"] = yd_human(result["total_space"])

    yd_print("{0:>7}: {1} ({2:.0f}%)".format("Used", result["used_space"], result["used_space_pct"]))
    yd_print("{0:>7}: {1}".format("Free", result["free_space"]))
    yd_print("{0:>7}: {1}".format("Total", result["total_space"]))


def yd_stat_cmd(options, args):
    """
    Вывод метаинформации об объекте в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) > 1:
        raise ydError(1, "Too many arguments")

    path = "/"
    if len(args) > 0:
        path = args[0]

    yd_print(yd_stat(options, yd_remote_path(path)))


def yd_ls_cmd(options, args):
    """
    Вывод списка файлов и директорий в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) > 1:
        raise ydError(1, "Too many arguments")

    path = "/"
    if len(args) > 0:
        path = args[0]

    result = listvalues(yd_list(options, yd_remote_path(path)))
    result.sort(key = lambda x: (x.type, x.name))

    for item in result:
        if item.isdir():
            size = "<dir>"
        elif options.human:
            size = yd_human(item.size)
        else:
            size = item.size

        if options.long:
            yd_print("{0}  {1:>25}  {2:>11}  {3}".format(item.created, item.modified, size, item.name))
        elif options.short:
            yd_print("{0}".format(item.name))
        else:
            yd_print("{0:>7}  {1}".format(size, item.name))


def yd_last_cmd(options, args):
    """
    Вывод метаинформации о последних загруженных файлах

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) > 1:
        raise ydError(1, "Too many arguments")

    limit = 0
    if len(args) > 0:
        try:
            limit = int(args[0])
            if limit < 1:
                raise ydError(1, "Limit must be greater than zero")
        except ValueError:
            raise ydError(1, "Limit must be integer")

    result = listvalues(yd_last(options, limit))
    result.sort(key = lambda x: (x.modified, x.created, x.name))

    for item in result:
        if options.human:
            size = yd_human(item.size)
        else:
            size = item.size

        if options.long:
            yd_print("{0}  {1:>25}  {2:>11}  {3}".format(item.created, item.modified, size, item.path[5:]))
        elif options.short:
            yd_print("{0}".format(item.path[5:]))
        else:
            yd_print("{0:>7}  {1}".format(size, item.path[5:]))


def yd_rm_cmd(options, args):
    """
    Обработчик удаления объекта хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) < 1:
        raise ydError(1, "File or directory not specified")

    for arg in args:
        yd_delete(options, yd_remote_path(arg))


def yd_cp_cmd(options, args):
    """
    Обработчик копироавния объекта в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) < 2:
        raise ydError(1, "Source or target not specified")
    if len(args) > 2:
        raise ydError(1, "Too many arguments")

    source = args[0]
    target = args[1]

    yd_copy(options, yd_remote_path(source), yd_remote_path(target))


def yd_mv_cmd(options, args):
    """
    Обработчик перемещения объекта в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) < 2:
        raise ydError(1, "Source or target not specified")
    if len(args) > 2:
        raise ydError(1, "Too many arguments")

    source = args[0]
    target = args[1]

    yd_move(options, yd_remote_path(source), yd_remote_path(target))


def yd_mkdir_cmd(options, args):
    """
    Обработчик создания директории в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) < 1:
        raise ydError(1, "Directory name not specified")

    for arg in args:
        yd_create(options, yd_remote_path(arg))


def yd_share_cmd(options, args):
    """
    Обработчик публикации объекта (объект становится доступен по прямой ссылке)

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) < 1:
        raise ydError(1, "Object name not specified")

    for arg in args:
        info = yd_publish(options, yd_remote_path(arg))
        yd_print("{0} -> {1}".format(info.path, info.public_url))


def yd_revoke_cmd(options, args):
    """
    Обработчик закрытия публичного доступа к объекту (объект становится недоступен по прямой ссылке)

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) < 1:
        raise ydError(1, "Object name not specified")

    for arg in args:
        yd_unpublish(options, yd_remote_path(arg))


def yd_put_cmd(options, args):
    """
    Обработчик загрузки файла в хранилище

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
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

    if not os.path.islink(source):
        target = yd_remote_path(target)
        if os.path.isdir(source):
            if os.path.basename(source) != "":
                source += "/"
            if os.path.basename(target) != "":
                target += "/"

            stat = yd_ensure_remote(options, target, "dir", yd_stat(options, target, True))

            if options.threads > 0:
                pool = ydPool(options.threads, initializer = yd_init_worker)
                try:
                    yd_put_sync(options, source, target, pool)
                    pool.yd_wait_async()
                    pool.close()
                    pool.join()
                except KeyboardInterrupt as e:
                    pool.terminate()
                    pool.join()
                    raise e
            else:
                yd_put_sync(options, source, target)

        elif os.path.isfile(source):
            stat = yd_ensure_remote(options, target, "file", yd_stat(options, target, True))
            if not (stat and stat.isfile() and os.path.getsize(source) == stat.size and yd_check_hash(options, source, stat.md5)):
                yd_put(options, source, target)
        else:
            raise ydError(1, "Unsupported filesystem object: {0}".format(source))
    else:
        yd_verbose("Skip: {0}".format(source), options.verbose)


def yd_get_cmd(options, args):
    """
    Обработчик получения файла из хранилища

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) < 1:
        raise ydError(1, "Source not specified")
    if len(args) > 2:
        raise ydError(1, "Too many arguments")

    source = yd_remote_path(args[0])

    if len(args) == 2:
        target = args[1]
    else:
        target = os.path.basename(source)

    stat = yd_stat(options, source)

    if stat.isdir():
        if target == "":
            target = "."
        if os.path.basename(source) != "":
            source += "/"
        if os.path.basename(target) != "":
            target += "/"

        yd_ensure_local(options, target, "dir")

        if options.threads > 0:
            pool = ydPool(options.threads, initializer = yd_init_worker)
            try:
                yd_get_sync(options, source, target, pool)
                pool.yd_wait_async()
                pool.close()
                pool.join()
            except KeyboardInterrupt as e:
                pool.terminate()
                pool.join()
                raise e
        else:
            yd_get_sync(options, source, target)

    elif stat.isfile():
        exists = yd_ensure_local(options, target, "file")
        if not exists or not (os.path.getsize(target) == stat.size and yd_check_hash(options, target, stat.md5)):
            yd_get(options, source, target)


def yd_du_cmd(options, args):
    """
    Обработчик оценки занимаемого места

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) > 1:
        raise ydError(1, "Too many arguments")

    if len(args) == 1:
        path = args[0]
    else:
        path = "/"

    if os.path.basename(path) != "":
        path += "/"

    result = yd_du(options, yd_remote_path(path))

    for name, size in result:
        name = name[5:-1]
        if len(name) == 0:
            name = "/"
        if options.human:
            yd_print("{0:>7}  {1}".format(yd_human(size), name))
        else:
            yd_print("{0:>12}  {1}".format(size, name))


def yd_clean_cmd(options, args):
    """
    Обработчик очистки файлов и директорий

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) > 1:
        raise ydError(1, "Too many arguments")

    if len(args) == 1:
        path = args[0]
    else:
        path = "/"

    if os.path.basename(path) != "":
        path += "/"

    yd_clean(options, path)


def yd_restore_cmd(options, args):
    """
    Обработчик восстановления файла из корзины

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) < 1:
        raise ydError(1, "Source or name not specified")
    if len(args) > 2:
        raise ydError(1, "Too many arguments")

    path = args[0]
    name = None

    if len(args) == 2:
        name = args[1]

    yd_restore(options, yd_remote_path(path), name)


def yd_token_cmd(options, args):
    """
    Получение OAuth токена для приложения

    Аргументы:
        options (ydOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) > 1:
        raise ydError(1, "Too many arguments")

    if len(args) == 0:
        yd_print("Open URL below in your browser, allow access and paste code as argument")
        yd_print("https://oauth.yandex.com/authorize?response_type=code&client_id={0}".format(options.appid))
        return

    method  = "POST"
    url     = "https://oauth.yandex.com/token"
    data    = "grant_type=authorization_code&code={0}&client_id={1}&client_secret={2}".format(args[0], options.appid, options.appsecret)
    headers = yd_headers(options.token)

    headers["Content-Type"]   = "application/x-www-form-urlencoded"
    headers["Content-Length"] = len(data)

    del headers["Authorization"]

    result = yd_query_retry(options, method, url, None, headers, None, data)

    yd_print("OAuth token is: {0}".format(result["access_token"]))


def yd_print_usage(cmd = None):
    """
    Вывод справки об использовании приложения и завершение работы

    Аргументы:
        cmd (str) -- Имя команды для которой выводится справка (пустое значение для справки по командам)
    """
    default = yd_default_config()

    if cmd == None or cmd == "help":
        yd_print("Usage:")
        yd_print("     {0} <command> [options] [args]".format(sys.argv[0]))
        yd_print("")
        yd_print("Commands:")
        yd_print("     help    -- describe the usage of this program or its subcommands")
        yd_print("     ls      -- list files and directories")
        yd_print("     rm      -- remove file or directory")
        yd_print("     cp      -- copy file or directory")
        yd_print("     mv      -- move file or directory")
        yd_print("     put     -- upload file to storage")
        yd_print("     get     -- download file from storage")
        yd_print("     mkdir   -- create directory")
        yd_print("     stat    -- show metainformation about cloud object")
        yd_print("     info    -- show metainformation about cloud storage")
        yd_print("     last    -- show metainformation about last uploaded files")
        yd_print("     share   -- publish uploaded object")
        yd_print("     revoke  -- unpublish uploaded object")
        yd_print("     du      -- estimate files space usage")
        yd_print("     clean   -- delete old files and/or directories")
        yd_print("     restore -- restore file or directory from trash")
        yd_print("     token   -- get oauth token for application")
        yd_print("")
        yd_print("Options:")
        yd_print("     --timeout=<N> -- timeout for api requests in seconds (default: {0})".format(default["timeout"]))
        yd_print("     --retries=<N> -- api call retries count (default: {0})".format(default["retries"]))
        yd_print("     --delay=<N>   -- api call delay between retries in seconds (default: {0})".format(default["delay"]))
        yd_print("     --limit=<N>   -- limit rows by one api call for listing files and directories (default: {0})".format(default["limit"]))
        yd_print("     --token=<S>   -- oauth token (default: none)")
        yd_print("     --quiet       -- suppress all errors (default: {0})".format(default["quiet"]))
        yd_print("     --verbose     -- verbose output (default: {0})".format(default["verbose"]))
        yd_print("     --debug       -- debug output (default: {0})".format(default["debug"]))
        yd_print("     --chunk=<N>   -- chunk size in KB for io operations (default: {0})".format(default["chunk"]))
        yd_print("     --ca-file=<S> -- file with trusted CAs (default: {0})".format("none" if not default["ca-file"] else default["ca-file"]))
        yd_print("     --ciphers=<S> -- ciphers sute (default: {0})".format("none" if not default["ciphers"] else default["ciphers"]))
        yd_print("     --version     -- print version and exit")
        yd_print("")
    elif cmd == "ls":
        yd_print("Usage:")
        yd_print("     {0} ls [options] [disk:/object]".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --human -- human-readable file size")
        yd_print("     --short -- short format (names only)")
        yd_print("     --long  -- long format (created, modified, size, name)")
        yd_print("")
        yd_print(" * If target is not specified, target will be root '/' directory")
        yd_print("")
    elif cmd == "rm":
        yd_print("Usage:")
        yd_print("     {0} rm <disk:/object1> [disk:/object2] ...".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --trash    -- remove to trash folder (default: {0})".format(default["trash"]))
        yd_print("     --poll=<N> -- poll time interval in seconds for asynchronous operations (default: {0})".format(default["poll"]))
        yd_print("     --async    -- do not wait (poll cheks) for completion (default: {0})".format(default["async"]))
        yd_print("")
    elif cmd == "cp":
        yd_print("Usage:")
        yd_print("     {0} cp <disk:/object1> <disk:/object2>".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --poll=<N> -- poll time interval in seconds for asynchronous operations (default: {0})".format(default["poll"]))
        yd_print("     --async    -- do not wait (poll cheks) for completion (default: {0})".format(default["async"]))
        yd_print("")
    elif cmd == "mv":
        yd_print("Usage:")
        yd_print("     {0} mv <disk:/object1> <disk:/object2>".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --poll=<N> -- poll time interval in seconds for asynchronous operations (default: {0})".format(default["poll"]))
        yd_print("     --async    -- do not wait (poll cheks) for completion (default: {0})".format(default["async"]))
        yd_print("")
    elif cmd == "put":
        yd_print("Usage:")
        yd_print("     {0} put <file> [disk:/object]".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --rsync                -- sync remote tree with local")
        yd_print("     --no-recursion         -- avoid descending in directories (default: {0})".format(default["no-recursion"]))
        yd_print("     --no-recursion-tag=<S> -- avoid descending in directories containing file (default: {0})".format("none" if not default["no-recursion-tag"] else default["no-recursion-tag"]))
        yd_print("     --exclude-tag=<S>      -- exclude contents of directories containing file (default: {0})".format("none" if not default["exclude-tag"] else default["exclude-tag"]))
        yd_print("     --skip-md5             -- skip md5 integrity checks (default: {0})".format(default["skip-md5"]))
        yd_print("     --threads=<N>          -- number of worker processes (default: {0})".format(default["threads"]))
        yd_print("     --iconv=<S>            -- try to restore file or directory names from the specified encoding if necessary (default: {0})".format("none" if not default["iconv"] else default["iconv"]))
        yd_print("")
        yd_print(" * If target is not specified, target will be root '/' directory")
        yd_print(" * If target specify a directory (ended with '/'), source file name will be added")
        yd_print(" * If target file exists, it will be silently overwritten")
        yd_print(" * Symbolic links are ignored")
        yd_print("")
    elif cmd == "get":
        yd_print("Usage:")
        yd_print("     {0} get <disk:/object> [file]".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --rsync        -- sync local tree with remote")
        yd_print("     --no-recursion -- avoid descending automatically in directories (default: {0})".format(default["no-recursion"]))
        yd_print("     --skip-md5     -- skip md5 integrity checks (default: {0})".format(default["skip-md5"]))
        yd_print("     --threads=<N>  -- number of worker processes (default: {0})".format(default["threads"]))
        yd_print("")
        yd_print(" * If target is not specified, source file name will be used")
        yd_print(" * If target exists, it will be silently overwritten")
        yd_print("")
    elif cmd == "mkdir":
        yd_print("Usage:")
        yd_print("     {0} mkdir <disk:/path1> [disk:/path2] ...".format(sys.argv[0]))
        yd_print("")
    elif cmd == "stat":
        yd_print("Usage:")
        yd_print("     {0} stat [disk:/object]".format(sys.argv[0]))
        yd_print("")
        yd_print(" * If target is not specified, target will be root '/' directory")
        yd_print("")
    elif cmd == "info":
        yd_print("Usage:")
        yd_print("     {0} info".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --long -- show sizes in bytes instead human-readable format")
        yd_print("")
    elif cmd == "last":
        yd_print("Usage:")
        yd_print("     {0} last [N]".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --human -- human-readable file size")
        yd_print("     --short -- short format (names only)")
        yd_print("     --long  -- long format (created, modified, size, name)")
        yd_print("")
        yd_print(" * If argument N is not specified, default REST API value will be used.")
        yd_print("")
    elif cmd == "share":
        yd_print("Usage:")
        yd_print("     {0} share <disk:/object1> [disk:/object2] ...".format(sys.argv[0]))
        yd_print("")
    elif cmd == "revoke":
        yd_print("Usage:")
        yd_print("     {0} revoke <disk:/object1> [disk:/object2] ...".format(sys.argv[0]))
        yd_print("")
    elif cmd == "du":
        yd_print("Usage:")
        yd_print("     {0} du [disk:/object]".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --depth=<N> -- show size if dir is N or fewer levels below target (default: {0})".format(default["depth"]))
        yd_print("     --long      -- show sizes in bytes instead human-readable format")
        yd_print("")
        yd_print(" * If target is not specified, target will be root '/' directory")
        yd_print("")
    elif cmd == "clean":
        yd_print("Usage:")
        yd_print("     {0} clean <options> [disk:/object]".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --dry      -- just print list of object to delete (default: {0})".format(default["dry"]))
        yd_print("     --type=<S> -- type of objects - 'file', 'dir' or 'all' (default: {0})".format(default["type"]))
        yd_print("     --keep=<S> -- keep criteria (default: none):")
        yd_print("                   * date ('2014-02-12T12:19:05+04:00')")
        yd_print("                   * relative interval ('7d', '4w', '1m', '1y')")
        yd_print("                   * number of objects ('31')")
        yd_print("")
        yd_print(" * If target is not specified, target will be root '/' directory")
        yd_print(" * Objects sorted and filtered by modified date (not created date)")
        yd_print("")
    elif cmd == "restore":
        yd_print("Usage:")
        yd_print("     {0} restore <trash:/object> [name]".format(sys.argv[0]))
        yd_print("")
        yd_print("Options:")
        yd_print("     --poll=<N> -- poll time interval in seconds for asynchronous operations (default: {0})".format(default["poll"]))
        yd_print("     --async    -- do not wait (poll cheks) for completion (default: {0})".format(default["async"]))
        yd_print("")
    elif cmd == "token":
        yd_print("Usage:")
        yd_print("     {0} token [code]".format(sys.argv[0]))
        yd_print("")
    else:
        sys.stderr.write("Unknown command {0}\n".format(cmd))
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc < 2:
        yd_print_usage()

    regexp  = re.compile("--config=(.*)")
    cfgfile = [match.group(1) for arg in sys.argv for match in [regexp.search(arg)] if match]

    if len(cfgfile) == 0:
        cfgfile = os.path.expanduser("~") + "/.ydcmd.cfg"
    else:
        cfgfile = cfgfile[0]

    args   = []
    config = yd_load_config(cfgfile)
    regexp = re.compile("^--(\S+?)(=(.*)){,1}$")
    for i in range(1, argc):
        arg = sys.argv[i]
        opt = regexp.split(arg)
        if len(opt) == 5:
            if opt[3] == None:
                opt[3] = True
            config[opt[1].lower()] = opt[3]
        else:
            args.append(arg)

    if "version" in config:
        yd_print("ydcmd v{0}".format(__version__))
        sys.exit(0)

    if len(args) == 0:
        yd_print_usage()

    options = ydOptions(config)

    command = args.pop(0).lower()
    if command == "help":
        command = None
        if len(args) == 1:
            command = args.pop(0).lower()
        yd_print_usage(command)

    if options.cafile == None:
        yd_verbose("Unsafe HTTPS connection - ca-file not used", options.verbose)

    try:
        if command == "ls":
            yd_ls_cmd(options, args)
        elif command == "rm":
            yd_rm_cmd(options, args)
        elif command == "cp":
            yd_cp_cmd(options, args)
        elif command == "mv":
            yd_mv_cmd(options, args)
        elif command == "put":
            yd_put_cmd(options, args)
        elif command == "get":
            yd_get_cmd(options, args)
        elif command == "mkdir":
            yd_mkdir_cmd(options, args)
        elif command == "stat":
            yd_stat_cmd(options, args)
        elif command == "info":
            yd_info_cmd(options, args)
        elif command == "last":
            yd_last_cmd(options, args)
        elif command == "share":
            yd_share_cmd(options, args)
        elif command == "revoke":
            yd_revoke_cmd(options, args)
        elif command == "du":
            yd_du_cmd(options, args)
        elif command == "clean":
            yd_clean_cmd(options, args)
        elif command == "restore":
            yd_restore_cmd(options, args)
        elif command == "token":
            yd_token_cmd(options, args)
        else:
            yd_print_usage(command)
    except ydError as e:
        if not options.quiet:
            sys.stderr.write("{0}\n".format(e.errmsg))
        sys.exit(e.errno if e.errno < 256 else int(e.errno / 100))
    except ydCertError as e:
        if not options.quiet:
            sys.stderr.write("{0}\n".format(e))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)
