from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import time
from datetime import datetime, timedelta
import random
from functools import wraps
import logging
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor, CancelledError  # ,wait
from math import trunc
import re
from operator import itemgetter
from functools import partial

# Extracted from `futures`
try:
    from multiprocessing import cpu_count
except ImportError:
    # some platforms don't have multiprocessing
    def cpu_count():
        return 0

try:
    from urllib.parse import unquote, urlparse

    unichr = chr
except ImportError:
    from urllib import unquote
    from urlparse import urlparse

try:
    import cPickle as pickle
except ImportError:
    import pickle

from distutils.dir_util import mkpath, remove_tree
from distutils.errors import DistutilsFileError
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests import Session
from requests.auth import AuthBase, HTTPBasicAuth, HTTPDigestAuth, extract_cookies_to_jar
from requests.cookies import cookielib, RequestsCookieJar
from clint.textui import progress as clint_progress


here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, 'VERSION'), mode='r') as fd:
    __version__ = fd.read().strip()

_py3plus = (sys.version_info[0] >= 3)  # Is Python version 3 and above?
if not _py3plus:
    _os_exit_force = partial(os._exit, -1)


# Default retry configuration

#: int: Default number of retries factor for :data:`_requests_extended_retries_factor`.
REQUESTS_EXTENDED_RETRIES_FACTOR = 1

#: int: Default number of retries on exception set through ``urllib3``'s `Retry` mechanism.
URLLIB3_BUILTIN_RETRIES_ON_EXCEPTION = 1

#: int: Default number of retries on exceptions raised while streaming the request content.
REQUESTS_RETRIES_ON_STREAM_EXCEPTION = 10

#: float: Default retry backoff factor.
RETRY_BACKOFF_FACTOR = 0.1

#: set: Default status codes to retry on intended for the underlying ``urllib3``.
URLLIB3_RETRY_STATUS_CODES = frozenset([413, 429, 500, 502, 503, 504])

#: set: Default status codes that should be avoided retrying on before handled
RETRY_EXEMPT_STATUS_CODES = frozenset([401, 407, 511])

COOKIE_STR_REGEX = re.compile(r'^\s*(?:[^,; =]+=[^,; ]+\s*(?:$|\s+|;\s*))+\s*$')
"""regex: A compiled regular expression object used to match the cookie string in the form of key/value pairs.

See also :meth:`BDownloader.__init__()` for more details about `cookies`.
"""

HTTP_HEADER_REGEX = re.compile(r'^\s*[a-zA-Z0-9_-]+:\s*[a-zA-Z0-9_ :;.,\\/"\'?!(){}[\]@<>=\-+*#$&`|~^%]*$')
"""regex: A compiled regular expression object used to validate the HTTP request header in the ``'name: value'`` format.

Refer to https://developers.cloudflare.com/rules/transform/request-header-modification/reference/header-format.
"""

_requests_extended_retries_factor = REQUESTS_EXTENDED_RETRIES_FACTOR
"""int: Number of retries that complements and extends the builtin `Retry` mechanism of ``urllib3``.

This global variable is meant for the decorator :func:`retry_requests()`, and its value can be modified through the 
module level function :func:`set_requests_retries_factor`. It is initialized to :const:`REQUESTS_EXTENDED_RETRIES_FACTOR`
by default, and usually you don't want to change it.

Together with ``urllib3``'s builtin retry logic, they determine the total number of the retries on exceptions and bad
status codes at requests for downloading. For more details on the retry mechanisms, see :func:`requests_retry_session`.

Notes:
    Don't mix these two retry mechanisms up with the retries at failed connections while streaming the request content.
"""

#: int: The highest pickle protocol number valid for both Python 2.x and Python 3.x.
PICKLE_PROTOCOL_NUMBER = 2


def _cpu_count():
    """A simple wrapper around the ``cpu_count()`` for escaping the `NotImplementedError`.

    Returns:
        int: The number of CPUs in the system. Return ``0`` if not obtained.
    """
    try:
        cpus = cpu_count()
    except NotImplementedError:
        cpus = 0

    return cpus


def set_requests_retries_factor(retries):
    """Set the retries factor for the decorator :func:`retry_requests`.

    Args:
        retries (int): Number of retries when a decorated method of ``requests`` raised an exception or returned any bad
            status code. It should take a value of at least ``1``, or else nothing changes.

    Returns:
        None.
    """
    global _requests_extended_retries_factor

    if retries > 0:
        _requests_extended_retries_factor = retries


def retry_requests(exceptions, status_exemptlist=RETRY_EXEMPT_STATUS_CODES, backoff_factor=0.1, logger=None):
    """A decorator that retries calling the wrapped ``requests``' function using an exponential backoff on exception.

    The retry attempt will be activated in the event of `exceptions` being caught and for all the bad status codes (i.e.
    codes ranging from 400 to 600) except the ones in `status_exemptlist`.

    Args:
        exceptions (:obj:`Exception` or :obj:`tuple` of :obj:`Exception`\ s): The exceptions to check against.
        status_exemptlist (set of int): A set of HTTP status codes that the retry should be avoided.
        backoff_factor (float): The backoff factor to apply between retries.
        logger (logging.Logger): An event logger.

    Returns:
        The wrapper function.

    Raises:
        `exceptions`: Re-raise the last caught exception when retries is exhausted.

    Notes:
        This function has an external dependency on the global variable :data:`_requests_extended_retries_factor`, whose
        value can be changed through the function :func:`set_requests_retries_factor`. Also, it should be greater than
        ``0``, thus allowing the decorated method to retry at least once to cover the edge cases of exceptions and bad
        status codes.

    References:
         [1] https://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/

         [2] https://en.wikipedia.org/wiki/Exponential_backoff
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    random.seed()

    def deco_retry(f):

        @wraps(f)
        def f_retry(*args, **kwargs):
            # The retry could be bypassed if the factor is not set through :func:`set_requests_retries_factor`,
            # e.g. by setting it to ``0`` directly. This behavior is intentionally not disabled.
            global _requests_extended_retries_factor

            ntries = 0
            while True:
                try:
                    r = f(*args, **kwargs)  # `r` is an instance of the ``requests.Response`` object
                    if not (status_exemptlist and r.status_code in status_exemptlist):
                        r.raise_for_status()
                    return r
                except exceptions as e:
                    ntries += 1
                    if ntries > _requests_extended_retries_factor:
                        raise e
                    steps = random.randrange(0, 2**ntries)
                    backoff = steps * backoff_factor

                    logger.warning("Retrying %d/%d in %.2f seconds: '%r'",
                                   ntries, _requests_extended_retries_factor, backoff, e)

                    time.sleep(backoff)

        return f_retry  # true decorator

    return deco_retry


class RequestsSessionWrapper(Session):
    """Subclass of the ``requests.Session`` class with extended `retry-on-exception` behavior for the ``get`` method.

    Note:
        The retry mechanism here is independent from that built into ``urllib3`` (see :data:`_requests_extended_retries_factor`
        and :func:`retry_requests`). That is, the decorated retry attempts will be triggered whenever the ``get`` method
        raised on some ``requests.RequestException`` or for any bad status code, regardless of whether or not the builtin
        Retry of ``urllib3`` is enabled. Nevertheless, they together determine the number of the total retries.
        See :func:`requests_retry_session` for more information about their cooperation.
    """
    #: Default timeouts: the connect timeout value defaults to 3.05 seconds, and the read timeout 6 seconds.
    TIMEOUT = (3.05, 6)

    def __init__(self, timeout=None, proxy=None, cookies=None, user_agent=None, referrer=None, verify=True, cert=None,
                 headers=None, auth=None, requester_cb=None):
        """Initialize the ``Session`` instance.

        The HTTP header ``User-Agent`` of the session is set to a default value of `bdownload/VERSION`, if not provided,
        with `VERSION` being replaced by the package's version number.

        Args:
            timeout (float or 2-tuple of float): Timeout value(s) as a float or ``(connect, read)`` tuple for both the
                ``connect`` and the ``read`` timeouts, respectively. If set to ``None``, ``0`` or ``()``, whether the
                whole or any item thereof, it will take a default value from :attr:`TIMEOUT`, accordingly.
            proxy (str): Same as for :meth:`BDownloader.__init__()`.
            cookies (str, dict or CookieJar): Same as for :meth:`BDownloader.__init__()`.
            user_agent (str): Same as for :meth:`BDownloader.__init__()`.
            referrer (str): Same as for :meth:`BDownloader.__init__()`.
            verify (bool or str): Same as for :meth:`requests.request()`.
            cert (str or tuple): Same as for :meth:`requests.request()`.
            headers (dict): Same meaning as in :meth:`BDownloader.__init__()`.
            auth (tuple or :class:`requests.auth.AuthBase`): Same meaning as in :meth:`BDownloader.__init__()`.
            requester_cb (func): The callback function provided by the downloader that uses the instantiated
                session object as the HTTP(S) requester. It will get called when making an HTTP GET request.
        """
        super(RequestsSessionWrapper, self).__init__()

        timeout = timeout or self.TIMEOUT
        if isinstance(timeout, tuple):
            timeout = timeout + self.TIMEOUT[len(timeout):]
            timeout = timeout[:len(self.TIMEOUT)]
            tmo_li = list(timeout)
            for idx, tm in enumerate(timeout):
                if not tm or tm < 0:
                    tmo_li[idx] = self.TIMEOUT[idx]
            timeout = tuple(tmo_li)
        else:  # float
            if timeout < 0:
                timeout = self.TIMEOUT

        self.timeout = timeout
        self.requester_cb = requester_cb

        if isinstance(headers, dict):
            self.headers.update(headers)

        self.referrer = referrer.strip() if referrer is not None else referrer
        if self.referrer:
            self.headers['Referer'] = self.referrer

        default_user_agent = 'bdownload/{}'.format(__version__)
        self.user_agent = user_agent if user_agent and user_agent.strip() else default_user_agent
        self.headers['User-Agent'] = self.user_agent

        if proxy is not None:
            self.proxies = dict(http=proxy, https=proxy)
        if cookies is not None:
            self.cookies = cookies if isinstance(cookies, (dict, cookielib.CookieJar)) else self._build_cookiejar_from_kvp(cookies)
        self.verify = verify
        self.cert = cert
        self.auth = auth

    @retry_requests(requests.RequestException, backoff_factor=RETRY_BACKOFF_FACTOR)
    def get(self, url, **kwargs):
        """Wrapper around ``requests.Session``'s `get` method decorated with the :func:`retry_requests` decorator.

        Args:
            url: URL for the file to download from.
            **kwargs: Same arguments as that ``requests.Session.get`` takes.

        Returns:
            ``requests.Response``: The response to the HTTP ``GET`` request.

        Raises:
            :class:`BDownloaderException`: Raised when the termination or cancellation flag has been set, for example,
                if :attr:`RequestsSessionWrapper.requester_cb` is initialized to :meth:`BDownloader.raise_on_interrupted`.
            ``requests.RequestException``: Raised when any of ``requests``'s exceptions occurred or bad status codes were
                received and retries have been exhausted.
            ExceptionByRequesterCB: Same exception(s) as that raised by :attr:`RequestsSessionWrapper.requester_cb`, if any.
        """
        if self.requester_cb:
            self.requester_cb()  # e.g. jump instantly out of the retries when interrupted by user

        kwargs.setdefault('timeout', self.timeout)

        if self.referrer == '*':
            self.headers.update({'Referer': url})

        return super(RequestsSessionWrapper, self).get(url, **kwargs)

    @staticmethod
    def _build_cookiejar_from_kvp(key_values):
        """Build a CookieJar from cookies in the form of key/value pairs.

        Args:
            key_values (str): The cookies must take the form of ``'cookie_key=cookie_value'``, with multiple pairs separated
                by whitespace and/or semicolon if applicable, e.g. ``'key1=val1 key2=val2; key3=val3'``.

        Returns:
            ``requests.cookies.RequestsCookieJar``: The built CookieJar for ``requests`` sessions.

        Raises:
            ValueError: Raised when the cookies string `key_values` is not in valid format.
        """
        if key_values:
            if not COOKIE_STR_REGEX.match(key_values):
                msg = 'Cookie {!r} is not in valid format!'.format(key_values)
                raise ValueError(msg)

            key_values = key_values.replace(';', ' ')  # Convert semicolons to whitespaces for ease of split

            cookiejar = RequestsCookieJar()
            kvps = key_values.split()
            for kvp in kvps:
                key, value = kvp.split("=")
                cookiejar.set(key, value)

            return cookiejar


def requests_retry_session(builtin_retries=None, backoff_factor=0.1, status_forcelist=None,
                           session=None, num_pools=20, pool_maxsize=20, **kwargs):
    """Create a session object of the class :class:`RequestsSessionWrapper` by default.

    Aside from the retry mechanism implemented by the wrapper decorator, the created session also leverages the built-in
    retries bound to ``urllib3``. When both of them are enabled, they cooperate to determine the total retry attempts.
    The worst-case retries is determined using the following formula:

        `builtin_retries` * (:data:`_requests_extended_retries_factor` + 1)

    which applies to all the exceptions and those status codes that fall into the `status_forcelist`. For other status
    codes, the maximum retries shall be :data:`_requests_extended_retries_factor`.

    Args:
        builtin_retries (int): Maximum number of retry attempts allowed on errors and interested status codes, which will
            apply to the retry logic of the underlying ``urllib3``. If set to `None` or ``0``, it will default to
            :const:`URLLIB3_BUILTIN_RETRIES_ON_EXCEPTION`.
        backoff_factor (float): The backoff factor to apply between retries.
        status_forcelist (set of int): A set of HTTP status codes that a retry should be enforced on. The default status
            forcelist shall be :const:`URLLIB3_RETRY_STATUS_CODES` if not given.
        session (:obj:`requests.Session`): An instance of the class ``requests.Session`` or its customized subclass.
            When not provided, it will use :class:`RequestsSessionWrapper` to create by default.
        num_pools (int): The number of connection pools to cache, which has the same meaning as `num_pools` in
            ``urllib3.PoolManager`` and will eventually be passed to it.
        pool_maxsize (int): The maximum number of connections to save that can be reused in the ``urllib3`` connection
            pool, which will be passed to the underlying ``requests.adapters.HTTPAdapter``.
        **kwargs: Same arguments as that :meth:`RequestsSessionWrapper.__init__()` takes.

    Returns:
        ``requests.Session``: The session instance with retry capability.

    References:
         https://www.peterbe.com/plog/best-practice-with-retries-with-requests
    """
    session = session or RequestsSessionWrapper(**kwargs)

    builtin_retries = builtin_retries or URLLIB3_BUILTIN_RETRIES_ON_EXCEPTION
    status_forcelist = status_forcelist or URLLIB3_RETRY_STATUS_CODES

    # Initialize the built-in retry mechanism and the connection pools
    max_retries = Retry(
        total=builtin_retries,
        read=builtin_retries,
        connect=builtin_retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=max_retries, pool_connections=num_pools, pool_maxsize=pool_maxsize, pool_block=True)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    return session


def unquote_unicode(string):
    """Unquote a percent-encoded string.

    Args:
        string (str): A %xx- and %uxxxx- encoded string.

    Returns:
        str: The unquoted unicode string.

    References:
        https://stackoverflow.com/questions/300445
    """
    try:
        if isinstance(string, unicode):  # python 2.7
            string = string.encode('utf-8')
        string = unquote(string)  # handle two-digit %hh components first
        parts = string.split(u'%u'.encode('utf-8'))
    except NameError:  # python 3.x has no type called `unicode`
        string = unquote(string)  # handle two-digit %hh components first
        parts = string.split('%u')

    if len(parts) > 1:
        res = [parts[0]]
        for part in parts[1:]:
            try:
                digits = part[:4].lower()
                if len(digits) < 4:
                    raise ValueError
                ch = unichr(int(digits, 16))
                if (
                    not res[-1] and
                    u'\uDC00' <= ch <= u'\uDFFF' and
                    u'\uD800' <= res[-2] <= u'\uDBFF'
                ):
                    # UTF-16 surrogate pair, replace with single non-BMP codepoint
                    res[-2] = (res[-2] + ch).encode(
                        'utf-16', 'surrogatepass').decode('utf-16')
                else:
                    res.append(ch)
                res.append(part[4:])
            except ValueError:
                res.append(u'%u')
                res.append(part)

        string = u''.join(res)

    try:
        if not isinstance(string, unicode):  # python 2.7
            string = string.decode("utf-8")
    except NameError:
        pass

    return string


class MillProgress(object):
    """Print a mill while progressing.

    This class is adapted from ``clint.textui.progress``, with added support for unknown `expected_size`.

    References:
         https://github.com/kennethreitz-archive/clint/blob/master/clint/textui/progress.py
    """
    STREAM = sys.stderr
    MILL_TEMPLATE = '{}  {}  {:,d}/{:<}  {}  {} {}\r'
    MILL_CHARS = ['|', '/', '-', '\\']

    NULL_EXPECTED_DISP = '--'
    NULL_EXPECTED_WIDTH = len(NULL_EXPECTED_DISP)

    # How long to wait before recalculating the ETA
    ETA_INTERVAL = 1
    # How many intervals (excluding the current one) to calculate the simple moving average
    ETA_SMA_WINDOW = 9

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.done()
        return False

    def __init__(self, label='', hide=None, expected_size=None, every=1, eta_tag='eta:', elapsed_tag='elapsed:'):
        self.label = label
        self.width = 0

        timetag_width = max(len(eta_tag), len(elapsed_tag))
        self.eta_tag = '{: >{width}}'.format(eta_tag, width=timetag_width)
        self.elapsed_tag = '{: >{width}}'.format(elapsed_tag, width=timetag_width)

        self.hide = hide
        # Only show bar in terminals by default (better for piping, logging etc.)
        if hide is None:
            try:
                self.hide = not self.STREAM.isatty()
            except AttributeError:  # output does not support isatty()
                self.hide = True
        self.expected_size = expected_size
        self.every = every
        self.last_progress = 0
        self.delta_progress = 0
        self.every_progress = 0
        self.start = time.time()
        self.elapsed = 0

        self.ittimes = []
        self.eta = 0
        self.etadelta = time.time()
        self.etadisp = self.format_time(self.eta)

        self.show(0)

    @staticmethod
    def format_time(seconds):
        td = timedelta(seconds=seconds)
        dt = datetime(1, 1, 1) + td

        return '{:02d}:{:02d}:{:02d}'.format(dt.hour, dt.minute, dt.second) if not any([dt.year-1, dt.month-1, dt.day-1]) else '--:--:--'

    def mill_char(self, progress):
        return self.MILL_CHARS[(progress // self.every) % len(self.MILL_CHARS)]

    def show(self, progress, count=None):
        if count is not None:
            self.expected_size = count

        self.last_progress = progress

        if self.expected_size and progress <= self.expected_size:
            if (time.time() - self.etadelta) > self.ETA_INTERVAL:
                self.etadelta = time.time()
                self.ittimes = \
                    self.ittimes[-self.ETA_SMA_WINDOW:] + \
                    [(time.time() - self.start) / (progress + 1)]
                self.eta = \
                    sum(self.ittimes) / len(self.ittimes) * \
                    (self.expected_size - progress)
                self.etadisp = self.format_time(self.eta)

            time_disp = self.etadisp
            time_label = self.eta_tag
        else:
            self.elapsed = time.time() - self.start
            elapsed_disp = self.format_time(self.elapsed)

            time_disp = elapsed_disp
            time_label = self.elapsed_tag

        expected_disp = '{:<{width},d}'.format(self.expected_size, width=self.NULL_EXPECTED_WIDTH) if self.expected_size else self.NULL_EXPECTED_DISP
        percent_disp = '{:6.2f}%'.format(trunc(progress/self.expected_size*100*100)/100) if self.expected_size else ''

        if not self.hide:
            if ((progress % self.every) == 0 or (progress - self.delta_progress) // self.every >= 1 or  # True every "every" updates
                    (self.expected_size and progress == self.expected_size)):  # And when we're done
                mill_bar = self.MILL_TEMPLATE.format(self.label, self.mill_char(self.every_progress),
                                                     progress, expected_disp, percent_disp, time_label, time_disp)
                mill_bar_len = len(mill_bar)
                if self.width > mill_bar_len:
                    mill_bar += ' ' * (self.width - mill_bar_len)
                self.width = mill_bar_len

                self.STREAM.write(mill_bar)
                self.STREAM.flush()

                self.delta_progress = progress
                self.every_progress += self.every

    def done(self):
        self.elapsed = time.time() - self.start
        elapsed_disp = self.format_time(self.elapsed)
        time_label = self.elapsed_tag
        expected_disp = '{:<{width},d}'.format(self.expected_size, width=self.NULL_EXPECTED_WIDTH) if self.expected_size else self.NULL_EXPECTED_DISP
        percent_disp = '{:6}%'.format(trunc(self.last_progress/self.expected_size*100)) if self.expected_size else ''

        if not self.hide:
            mill_bar = self.MILL_TEMPLATE.format(self.label, ' ', self.last_progress, expected_disp, percent_disp,
                                                 time_label, elapsed_disp)
            mill_bar_len = len(mill_bar)
            if self.width > mill_bar_len:
                mill_bar += ' ' * (self.width - mill_bar_len)
            self.width = mill_bar_len

            self.STREAM.write(mill_bar)
            self.STREAM.write('\n')
            self.STREAM.flush()


class HTTPBasicAuthEx(HTTPBasicAuth):
    """Attaches HTTP Basic Authentication to the given Request object.

    This class is adapted from ``requests.auth.HTTPBasicAuth`` and ``requests.auth.HTTPDigestAuth``, with added support
    for handling `Unauthorized` request on the response.

    References:
         https://github.com/psf/requests/blob/main/src/requests/auth.py
    """
    def __init__(self, username, password):
        super(HTTPBasicAuthEx, self).__init__(username, password)

    def handle_401(self, r, **kwargs):
        """Takes the given response and tries basic-auth, if needed."""
        if not 400 <= r.status_code < 500:
            return r

        s_auth = r.headers.get('www-authenticate', '')
        if 'basic' in s_auth.lower():
            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            r.content
            r.close()
            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep = self.__call__(prep)
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        return r


class BDownloader(object):
    """The class for executing and managing download jobs.

    The context of the current downloading job is structured as::

        ctx = {
            "total_size": 2000,  # total size of all the to-be-downloaded files, maybe inaccurate due to chunked transfer encoding
            "accurate": True,  # Is `total_size` accurate?
            "last_progress": 0,  # the overall progress, in bytes, from last run loaded when resuming from interruption
            "downloaded": 0,  # newly accumulated bytes from this run of downloads, which are updated on completion of every worker thread
            "orig_path_urls": [('file1', 'url1\turl2\turl3'), ('file2', 'url4\turl5\turl6')],  # originally added downloads,
                # which don't necessarily correspond to `files` e.g. due to duplicate or interruption
            "file_cnt": 2,  # number of current downloading files, i.e. `alt_files`
            "alt_files": [("full_path_to_file1", `ctx_file1_obj`), ("full_path_to_file2", `ctx_file2_obj`)],  # flattened `files`
                # with the exception of the succeeded on addition
            "active_files": [("full_path_to_file1", `ctx_file1_obj`)],  # scheduled, in-processing file downloads
            "active_downloads": 1,  # number of in-processing file downloads
            "next_download": 1,  # index to the next to schedule to download file
            "poll_changed": False,  # Have the polled files' states changed?
            "files":{
                "full_path_to_file1":{
                    "length": 2000,  # 0 means 'unknown', i.e. file size can't be pre-determined through any one of provided URLs
                    "progress": 0,  # `SUCCEEDED` downloaded bytes: initialized to 0, set to the last progress when
                                    # resuming and updated on completion (SUCCEEDED only!) of every task (`Future`)
                    "last_progress": 0,  # CONSTANT: the loaded progress of last run upon resuming from interruption
                    "downloaded": 0,  # downloaded bytes: initialized to 0, and updated on completion (SUCCEEDED, FAILED)
                                      # of every task (`Future`)
                    "stdout": False,  # standard output
                    "resumable": True,
                    "resuming_from_intr": False,  # Are we resuming from keyboard interruption?
                    "download_state": "inprocess",
                    "cancelled_on_exception": False,
                    "orig_path_url": ('file1', 'url1\turl2\turl3'),  # (path, url) as a subparameter passed to :meth:`downloads`
                    "path_url": ('full_path_to_file1', 'url1\turl2\turl3'),  # (full_pathname, active_URLs)
                    "urls":{"url1":{"auth": None, "auth_header": {"Authorization": "Basic dXNlcjpwYXNz"}, "accept_ranges": "bytes", "refcnt": 1, "interrupted": 2, "succeeded": -5},
                            "url2":{"auth": None, "auth_header": {"Authorization": "Digest username='user',realm=..."}, "accept_ranges": "none", "refcnt": 0, "interrupted": 0, "succeeded": 0},
                            "url3":{"auth": None, "auth_header": {}, "accept_ranges": "bytes", "refcnt": 1, "interrupted": 0, "succeeded": -2}},
                    "alt_ranges": [("bytes=1000-1999", `ctx_range2_obj`)],  # task ranges stack
                    "worker_ranges": [("bytes=0-999", `ctx_range1_obj`)],  # active range downloading tasks
                    "active_workers": 1,  # number of active worker threads on ranges downloading of the file
                    "ranges_succeeded": 0,  # number of ranges successfully downloaded
                    "ranges":{
                        "bytes=0-999": {
                            "start": 0,  # start byte position
                            "end": 999,  # end byte position, None for 'unkown', see above
                            "offset": 0,  # current pointer position relative to 'start'(i.e. 0)
                            "last_offset": 0,  # the last pointer position where the range task failed and was rescheduled in this run
                            "start_time": 0,
                            "rt_dl_speed": 0,  # x seconds interval
                            "download_state": "inprocess",
                           "future": future1,
                           "url": [url1],
                           "alt_urls": {}
                        },
                        "bytes=1000-1999": {
                            "start":1000,
                            "end":1999,
                            "offset": 0,  # current pointer position relative to 'start'(i.e. 1000)
                            "last_offset": 0,  # the last pointer position where the range task failed and was rescheduled in this run
                            "start_time": 0,
                            "rt_dl_speed": 0,  # x seconds interval
                            "download_state": "inprocess",
                            "future": future2,
                            "url": [url3],
                            "alt_urls": {}
                        }
                    }
                },
                "full_path_to_file2":{
                }
            }
        }
    """
    STD_OUT = '-'            # the qualified file name reserved for standard output

    INPROCESS_EXT = '.bdl'        # extension for the file in downloading (i.e. not succeeded yet)
    RESUM_PARTS_EXT = '.bdl.par'  # extension for the resumption parts file

    # Possible download states of the files and ranges
    PENDING = 'pending'      # submitted but not yet processed
    INPROCESS = 'inprocess'  # in downloading
    FAILED = 'failed'        # aborted with exception raised
    SUCCEEDED = 'succeeded'  # finished without error
    CANCELLED = 'cancelled'  # aborted without being processed

    _COMPLETED = {FAILED, CANCELLED, SUCCEEDED}

    _FILE_STATES = [PENDING, INPROCESS, FAILED, CANCELLED, SUCCEEDED]
    _RANGE_STATES = [PENDING, INPROCESS, FAILED, CANCELLED, SUCCEEDED]

    # Progress bar styles
    PROGRESS_BS_MILL = 'mill'
    PROGRESS_BS_BAR = 'bar'
    PROGRESS_BS_NONE = 'none'

    _PROGRESS_BAR_STYLES = {PROGRESS_BS_MILL, PROGRESS_BS_BAR, PROGRESS_BS_NONE}

    # Default value for `max_workers`
    _MAX_WORKERS = (_cpu_count() or 1) * 5  # In line with `futures`

    # Default chunk size for streaming the download
    _STREAM_CHUNK_SIZE = 7168

    # The timeout value to allow the waiting event to be interruptible
    _INTERRUPTIBLE_WAIT_TIMEOUT = 0.5
    # The number of time to wait in seconds before shutdown when interrupted on Python2.x
    _PY2_SIGINT_WAIT_TIMEOUT = 3
    # The number of time to wait in seconds for joining the thread when interrupted on Python2.x
    _PY2_SIGINT_JOIN_TIMEOUT = 1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __init__(self, max_workers=None, max_parallel_downloads=5, workers_per_download=4, min_split_size=1024*1024,
                 chunk_size=1024*100, proxy=None, cookies=None, user_agent=None, logger=None, progress='mill',
                 num_pools=20, pool_maxsize=20, request_timeout=None, request_retries=None, status_forcelist=None,
                 resumption_retries=None, continuation=True, referrer=None, check_certificate=True, ca_certificate=None,
                 certificate=None, auth=None, netrc=None, headers=None):
        """Create and initialize a :class:`BDownloader` object.

        Args:
            max_workers (int): The `max_workers` parameter specifies the number of the parallel downloading threads,
                whose default value is determined by ``#num_of_processor * 5`` if set to `None`.
            max_parallel_downloads (int): `max_parallel_downloads` limits the number of files downloading concurrently.
                It has a default value of 5.
            workers_per_download (int): `workers_per_download` sets the maximum number of worker threads for every file
                downloading job, which defaults to 4.
            min_split_size (int): `min_split_size` denotes the size in bytes of file pieces split to be downloaded
                in parallel, which defaults to 1024*1024 bytes (i.e. 1MB).
            chunk_size (int): The `chunk_size` parameter specifies the chunk size in bytes of every http range request,
                which will take a default value of 1024*100 (i.e. 100KB) if not provided.
            proxy (str): The `proxy` supports both HTTP and SOCKS proxies in the form of ``'http://[user:pass@]host:port'``
                and ``'socks5://[user:pass@]host:port'``, respectively.
            cookies (str, dict or CookieJar): If `cookies` needs to be set, it must either take the form of ``'cookie_key=cookie_value'``,
                with multiple pairs separated by whitespace and/or semicolon if applicable, e.g. ``'key1=val1 key2=val2;key3=val3'``,
                be packed into a ``dict``, or be an instance of ``CookieJar``, i.e. ``cookielib.CookieJar`` for Python27,
                ``http.cookiejar.CookieJar`` for Python3.x or ``RequestsCookieJar`` from ``requests``.
            user_agent (str): When `user_agent` is not given, it will default to ``'bdownload/VERSION'``, with ``VERSION``
                being replaced by the package's version number.
            logger (logging.Logger): The `logger` parameter specifies an event logger. If `logger` is not `None`,
                it must be an object of class :class:`logging.Logger` or of its customized subclass.  Otherwise,
                it will use a default module-level logger returned by ``logging.getLogger(__name__)``.
            progress (str): `progress` determines the style of the progress bar displayed while downloading files.
                Possible values are ``'mill'``, ``'bar'`` and ``'none'``. ``'mill'`` is the default. To disable this
                feature, e.g. while scripting or multi-instanced, set it to ``'none'``.
            num_pools (int): The `num_pools` parameter has the same meaning as `num_pools` in ``urllib3.PoolManager``
                and will eventually be passed to it. Specifically, `num_pools` specifies the number of connection pools
                to cache.
            pool_maxsize (int): `pool_maxsize` will be passed to the underlying ``requests.adapters.HTTPAdapter``.
                It specifies the maximum number of connections to save that can be reused in the urllib3 connection pool.
            request_timeout (float or 2-tuple of float): The `request_timeout` parameter specifies the timeouts for the
                internal ``requests`` session. The timeout value(s) as a float or ``(connect, read)`` tuple is intended
                for both the ``connect`` and the ``read`` timeouts, respectively. If set to ``None``, it will take a
                default value of :attr:`RequestsSessionWrapper.TIMEOUT`.
            request_retries (int): `request_retries` specifies the maximum number of retry attempts allowed on exceptions
                and interested status codes(i.e. `status_forcelist`) for the builtin Retry logic of ``urllib3``. It will
                default to :const:`URLLIB3_BUILTIN_RETRIES_ON_EXCEPTION` if not given.

                Notes:
                    There are two retry mechanisms that jointly determine the total retries of a request. One is the
                    above-mentioned Retry logic that is built into ``urllib3``, and the other is the extended high-level
                    retry factor that is meant to complement the builtin retry mechanism. The total retries is bounded by
                    the following formula:

                    `request_retries` * (:data:`_requests_extended_retries_factor` + 1)

                    See :func:`retry_requests`, :class:`RequestsSessionWrapper` and :func:`requests_retry_session` for
                    more details on the retry mechanisms.
            status_forcelist (set of int): `status_forcelist` specifies a set of HTTP status codes that a retry should
                be enforced on. The default set of status codes shall be :const:`URLLIB3_RETRY_STATUS_CODES` if not given.
            resumption_retries (int): The `resumption_retries` parameter specifies the maximum allowable number of retries
                on error at resuming the interrupted download while streaming the request content. The default value of it
                is :const:`REQUESTS_RETRIES_ON_STREAM_EXCEPTION` when not provided.
            continuation (bool): The `continuation` parameter specifies whether, if possible, to resume the partially
                downloaded files before, e.g. when the downloads had been terminated by the user by pressing `Ctrl-C`.
                When not present, it will default to `True`.
            referrer (str): `referrer` specifies an HTTP request header ``Referer`` that applies to all downloads.
                If set to ``'*'``, the request URL shall be used as the referrer per download.
            check_certificate (bool): The `check_certificate` parameter specifies whether to verify the server's TLS
                certificate or not. It defaults to `True`.
            ca_certificate (str): The `ca_certificate` parameter specifies a path to the preferred CA bundle file (.pem)
                or directory with certificates in PEM format of trusted CAs. If set to a path to a directory, the directory
                must have been processed using the ``c_rehash`` utility supplied with OpenSSL, according to ``requests``.
                NB the cert files in the directory each only contain one CA certificate.
            certificate (str or tuple): `certificate` specifies a client certificate. It has the same meaning as that of
                `cert` in :meth:`requests.request()`.
            auth (tuple or :class:`requests.auth.AuthBase`): The `auth` parameter sets a (user, pass) tuple or Auth handler
                to enable Basic/Digest/Custom HTTP Authentication. It will be passed down to the underlying :class:`requests.Session`
                instance as the default authentication.

                Warning:
                    The `auth` will be applied to all the downloads for HTTP Authentication. Don't use this parameter,
                    if not all of the downloads need the authentication, to avoid leaking credential. Instead, use
                    the **netrc** parameter for fine-grained control over HTTP Authentication.
            netrc (dict): `netrc` specifies a dictionary of ``'machine': (login, password)`` (or ``'machine': requests.auth.AuthBase``)
                for HTTP Authentication, similar to the .netrc file format in spirit.
            headers(dict): `headers` specifies extra HTTP headers, standard or custom, for use in all of the requests
                made by the session. The headers take precedence over the ones specified by other parameters, e.g. **user_agent**,
                if conflict happens.

        Raises:
            ValueError: Raised when the `cookies` is of the :obj:`str` type and not in valid format.
        """
        if not resumption_retries or resumption_retries < 0:
            # Fall back on the defaults if None, 0 or a negative number is given
            resumption_retries = REQUESTS_RETRIES_ON_STREAM_EXCEPTION
        self.resumption_retries = resumption_retries

        if not request_retries or request_retries < 0:
            # Fall back on the defaults if None, 0 or a negative number is given
            request_retries = URLLIB3_BUILTIN_RETRIES_ON_EXCEPTION

        verify = ca_certificate if check_certificate and ca_certificate else check_certificate

        self.auth = auth
        self.netrc = netrc

        session = RequestsSessionWrapper(timeout=request_timeout, proxy=proxy, cookies=cookies, user_agent=user_agent,
                                         referrer=referrer, verify=verify, cert=certificate, headers=headers, auth=None,
                                         requester_cb=self.raise_on_interrupted)
        self.requester = requests_retry_session(session=session, builtin_retries=request_retries,
                                                backoff_factor=RETRY_BACKOFF_FACTOR,
                                                status_forcelist=status_forcelist,
                                                num_pools=num_pools, pool_maxsize=pool_maxsize)

        self.max_parallel_downloads = max_parallel_downloads
        self.workers_per_download = workers_per_download
        if max_workers is None:
            max_workers = self._MAX_WORKERS
        self.max_workers = max(max_workers, self.max_parallel_downloads * self.workers_per_download)
        self.executor = ThreadPoolExecutor(self.max_workers)

        self.progress_thread = None
        self.mgmnt_thread = None
        self.all_done_event = threading.Event()  # Event signaling the completion of all the download jobs
        self.all_done = False  # Flag denoting the completion of all the download jobs
        # Flag indicating that **all** the download tasks have been submitted, i.e. no more downloads to be added
        self.all_submitted = False
        self.sigint = False  # Received the SIGINT (i.e. `KeyboardInterrupt`) signal, e.g. raised by hitting `Ctrl-C`?
        self.cmdquit = False  # Received the QUIT command, e.g. triggered by pressing `q`?
        # Flag indicating that cancellation of all the tasks have been done on demand, e.g. by pressing `Ctrl-C` or `q`
        self.cancelled_on_interrupt = False
        self.stop = False  # Flag signaling waiting threads to exit
        # The download context that maintains the status of the downloading files and the corresponding chunks
        self._dl_ctx = {'total_size': 0, 'accurate': True, 'last_progress': 0, 'downloaded': 0, 'orig_path_urls': [],
                        'file_cnt': 0, 'files': {}, 'alt_files': [], 'active_files': [], 'next_download': 0,
                        'active_downloads': 0, 'poll_changed': False}

        # list: A downloadable subset of all the `(path, url)`\ s that were passed to :meth:`BDownloader.download` or
        # :meth:`BDownloader.downloads`.
        self.active_downloads_added = []
        # list: The non-downloadable `(path, url)`\ s that were filtered out before downloading actually begins.
        # Together with :attr:`BDownloader.active_downloads_added`, they form the whole of the input downloads.
        self.failed_downloads_on_addition = []
        # list: A subset of :attr:`BDownloader.active_downloads_added`, the downloading of which aborted abnormally.
        self.failed_downloads_in_running = []
        # list: The succeeded downloads, being a subset of :attr:`BDownloader.active_downloads_added`.
        self.succeeded_downloads_in_running = []
        # list: The downloads whose desired files already exist out there, without the need to re-download.
        self.succeeded_downloads_on_addition = []

        if logger is None:
            logger = logging.getLogger(__name__)
        self._logger = logger

        self.min_split_size = min_split_size
        self.chunk_size = chunk_size

        self.progress = progress
        if self.progress not in self._PROGRESS_BAR_STYLES:
            self._logger.error("Error: invalid ProgressBar parameter '%s', default to '%s'",
                               self.progress, self.PROGRESS_BS_MILL)
            self.progress = self.PROGRESS_BS_MILL

        self.continuation = continuation

    @staticmethod
    def calc_req_ranges(req_len, split_size, req_start=0):
        """Split the request `req_len` into chunks of the size `split_size` starting from the point `req_start`.

        Args:
            req_len (int): The length of the request to split.
            split_size (int): The size of each split chunk.
            req_start (int): The start position to split from.

        Returns:
            list of tuple: The list of ranges in the form of 2-tuple ``'(start ,end)'``.
        """
        ranges = []
        range_cnt = req_len // split_size
        for piece_id in range(range_cnt):
            start = req_start + piece_id * split_size
            end = start + split_size - 1
            ranges.append((start, end))

        # get the range of the last file piece
        if req_len % split_size:
            start = req_start + range_cnt * split_size
            end = req_start + req_len - 1
            ranges.append((start, end))

        return ranges

    @staticmethod
    def list_split(li, chunk_size=5):
        """Break a list into chunks.

        Args:
            li (list): The list to split.
            chunk_size (int): The size of the resultant chunk list.

        Yields:
            list: The next chunk of the split list `li`.
        """
        for i in range(0, len(li), chunk_size):
            yield li[i:i+chunk_size]

    def _is_parallel_downloadable(self, path_name):
        """Check if the file can be downloaded in parallel, i.e. using multi-threads to download the file pieces simultaneously.

        Args:
            path_name (str): The full path name of the file to be downloaded.

        Returns:
            bool: ``True`` if the file length is known and the server accepts its range requests, otherwise ``False``.
        """
        ctx_file = self._dl_ctx['files'][path_name]
        parallel = True if ctx_file['length'] and ctx_file['resumable'] and not ctx_file['stdout'] else False
        return parallel

    def _is_download_resumable(self, path_name):
        """Check if the current download of the file can be resumed from the point of last interruption through retrying.

        Args:
            path_name (str): The full path name of the file being downloaded.

        Returns:
            bool: ``True`` if the server accepts range requests for the file, otherwise ``False``.
        """
        return True if self._dl_ctx['files'][path_name]['resumable'] else False

    def raise_on_interrupted(self):
        """Raise a customized exception signaling that the downloads have been terminated by the user.

        Raises:
            :class:`BDownloaderException`: Raised when the termination or cancellation flag has been set.
        """
        if self.sigint or self.cmdquit:
            raise BDownloaderException("The download was intentionally interrupted by the user!")

    def _get_remote_file_multipart(self, path_name, req_range):
        """The worker thread body for downloading an assigned piece of a file.

        Args:
            path_name (str): The full path name of the file to be downloaded.
            req_range (str): A chunk of the file `path_name` as a range request of the form ``'bytes=start-end'``.

        Returns:
            None.

        Raises:
            :class:`BDownloaderException`: Raised when connect timeouts, read timeouts, failed connections or bad status
                codes occurred and the retries is exhausted.
            EnvironmentError: Raised when file operations failed.
        """
        ctx_file = self._dl_ctx['files'][path_name]
        ctx_range = ctx_file['ranges'][req_range]
        url = ctx_range['url'][0]

        alt_urls = None  # get-on-error alternative URLs
        alt_try = 0  # number of tries at alternative URLs
        max_retries = self.resumption_retries

        ctx_range['download_state'] = self.INPROCESS
        if ctx_file['download_state'] == self.PENDING:
            ctx_file['download_state'] = self.INPROCESS

        path_name_inprocess = path_name + self.INPROCESS_EXT
        try:
            with open(path_name_inprocess, mode='r+b') as fd:
                for tr in range(max_retries+1):
                    # request start position and end position, maybe resuming from a previous failed request
                    range_start, range_end = ctx_range['start'] + ctx_range['offset'], ctx_range['end']
                    ranges = self.calc_req_ranges(range_end - range_start + 1, self.chunk_size, range_start)

                    fd.seek(range_start)

                    for start, end in ranges:
                        req_range_new = "bytes={}-{}".format(start, end)
                        headers = {"Range": req_range_new}
                        headers.update(ctx_file['urls'][url]['auth_header'])

                        try:
                            r = self.requester.get(url, headers=headers, allow_redirects=True, stream=True, auth=ctx_file['urls'][url]['auth'])
                            if r.status_code == requests.codes.partial:
                                try:
                                    for chunk in r.iter_content(chunk_size=self._STREAM_CHUNK_SIZE):
                                        fd.write(chunk)
                                        ctx_range['offset'] += len(chunk)

                                        self.raise_on_interrupted()
                                except requests.RequestException as e:
                                    self._logger.error("Error while downloading '%s'(range:%d-%d/%d-%d): '%r'",
                                                       os.path.basename(path_name), start, end, ctx_range['start'],
                                                       ctx_range['end'], e)

                                    # increment the interrupted connection count
                                    ctx_url = ctx_range['alt_urls'].setdefault(url, {})
                                    ctx_url['interrupted'] = ctx_url.get('interrupted', 0) + 1

                                    break
                            else:
                                msg = "Unexpected status code {}, which should have been {}.".format(r.status_code, requests.codes.partial)
                                raise requests.RequestException(msg)
                        except requests.RequestException as e:
                            msg = "Error while downloading '{}'(range:{}-{}/{}-{}): '{!r}'".format(
                                os.path.basename(path_name), start, end, ctx_range['start'], ctx_range['end'], e)
                            self._logger.error(msg)

                            # increment the failed connection count
                            ctx_url = ctx_range['alt_urls'].setdefault(url, {})
                            ctx_url['interrupted'] = ctx_url.get('interrupted', 0) + 1

                            if alt_urls is None:
                                # Get alternative URLs from sorted sources used to resume downloading from
                                alt_urls_sorted = self._get_alt_urls(path_name)
                                alt_urls = [alt_url for alt_url in alt_urls_sorted if alt_url != url]

                            if not alt_urls or alt_try >= len(alt_urls):
                                raise BDownloaderException(msg)
                            else:
                                url = alt_urls[alt_try]
                                alt_try += 1

                                ctx_range['alt_urls'][url] = {'refcnt': 1}
                                ctx_range['url'].append(url)

                                break
                    else:
                        break

                    if tr < max_retries:
                        self._logger.error("Retrying %d/%d: '%s' at '%s'",
                                           tr + 1, max_retries, os.path.basename(path_name), url)
                        time.sleep(0.1)
                else:
                    msg = "Task error while downloading '{}'(range: {}-{})".format(os.path.basename(path_name),
                                                                                   ctx_range['start'], ctx_range['end'])
                    raise BDownloaderException(msg)
        except EnvironmentError as e:
            self._logger.error("Error while operating on '%s': 'Error number %d: %s'", path_name_inprocess, e.errno, e.strerror)

            raise

    def _get_remote_file_singlewhole(self, path_name, req_range):
        """The worker thread body for downloading the whole of a file, as opposed to :meth:`_get_remote_file_multipart`.

        Args:
            path_name (str): The full path name of the file to be downloaded.
            req_range (str): The whole chunk of the file `path_name` as a mock range request of the form ``'bytes=0-None'``.

        Returns:
            None.

        Raises:
            :class:`BDownloaderException`: Raised when connect timeouts, read timeouts, failed connections or bad status
                codes occurred and the retries is exhausted.
            EnvironmentError: Raised when file operations failed.
        """
        ctx_file = self._dl_ctx['files'][path_name]
        ctx_range = ctx_file['ranges'][req_range]
        url = ctx_range['url'][0]

        # Get alternative URLs from sorted sources used to resume downloading from
        alt_urls = [alt_url for alt_url in self._get_alt_urls(path_name) if alt_url != url]
        alt_try = 0  # number of tries at alternative URLs
        max_retries = self.resumption_retries
        range_req_satisfiable = True  # The serve may choose to ignore the `Range` header

        range_end = file_end = ctx_file['length'] if ctx_file['length'] else ''

        ctx_range['download_state'] = self.INPROCESS
        if ctx_file['download_state'] == self.PENDING:
            ctx_file['download_state'] = self.INPROCESS

        is_stdout = path_name == self.STD_OUT
        path_name_inprocess = path_name + self.INPROCESS_EXT if not is_stdout else self.STD_OUT
        fd = None
        try:
            if not is_stdout:
                fd = open(path_name_inprocess, mode='r+b')
                writeb = fd.write
            else:
                writeb = partial(os.write, sys.stdout.fileno())
                if not _py3plus and sys.platform == 'win32':
                    # set sys.stdout to binary mode: (https://github.com/palantir/python-language-server/blob/develop/pyls/__main__.py)
                    import msvcrt
                    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

            for tr in range(max_retries+1):
                skip = 0
                # request start position, maybe resuming from a previous failed request
                range_start = ctx_range['start'] + ctx_range['offset']
                if not is_stdout:
                    fd.seek(range_start)

                if self._is_download_resumable(path_name) and range_req_satisfiable and ctx_range['offset']:
                    req_range_new = "bytes={}-{}".format(range_start, '')
                    headers = {"Range": req_range_new}
                    status_code = requests.codes.partial
                else:
                    headers = {}
                    status_code = requests.codes.ok
                    skip = range_start
                headers.update(ctx_file['urls'][url]['auth_header'])

                try:
                    r = self.requester.get(url, headers=headers, allow_redirects=True, stream=True, auth=ctx_file['urls'][url]['auth'])
                    if r.status_code == status_code:
                        try:
                            for chunk in r.iter_content(chunk_size=self._STREAM_CHUNK_SIZE):
                                if skip:
                                    skip -= len(chunk)
                                    continue
                                writeb(chunk)
                                ctx_range['offset'] += len(chunk)

                                if headers:
                                    range_start = ctx_range['start'] + ctx_range['offset']

                                self.raise_on_interrupted()

                            break
                        except requests.RequestException as e:
                            self._logger.error("Error while downloading '%s'(range:%s-%s/%s-%s): '%r'",
                                               os.path.basename(path_name), range_start, range_end,
                                               ctx_range['start'], file_end, e)
                    else:
                        msg = "Unexpected status code {}, which should have been {}. " \
                              "This may be caused by ignored range request.".format(r.status_code, status_code)
                        self._logger.error(msg)

                        # In case the server responds with a '200' status code against a range request
                        if (not alt_urls or alt_try >= len(alt_urls)) and r.status_code == requests.codes.ok:
                            range_req_satisfiable = False
                        else:
                            raise requests.RequestException(msg)
                except requests.RequestException as e:
                    msg = "Error while downloading '{}'(range:{}-{}/{}-{}): '{!r}'".format(
                        os.path.basename(path_name), range_start, range_end, ctx_range['start'], file_end, e)
                    self._logger.error(msg)

                    if not alt_urls or alt_try >= len(alt_urls):
                        raise BDownloaderException(msg)
                    else:
                        url = alt_urls[alt_try]
                        alt_try += 1

                if tr < max_retries:
                    self._logger.error("Retrying %d/%d: '%s' at '%s'",
                                       tr + 1, max_retries, os.path.basename(path_name), url)
                    time.sleep(0.1)
            else:
                msg = "Task error while downloading '{}'(range: {}-{})".format(os.path.basename(path_name),
                                                                               ctx_range['start'], "")
                raise BDownloaderException(msg)
        except EnvironmentError as e:
            self._logger.error("Error while operating on '%s': 'Error number %d: %s'", path_name_inprocess, e.errno, e.strerror)

            raise
        finally:
            if fd:
                fd.flush()
                fd.close()
            if is_stdout:
                sys.stdout.flush()

    def _pick_file_url(self, path_name):
        """Select one URL from the multiple sources of the file to download from.

        Args:
            path_name (str): The full path name of the file to be downloaded.

        Yields:
            list: A list of URL(s) to download the file from using a strategy of ``Round Robin``.
        """
        STRIPE_WIDTH = 3

        ctx_file_urls = self._dl_ctx['files'][path_name]['urls']
        if self._is_download_resumable(path_name):
            urls = [url for url, ctx_url in ctx_file_urls.items() if ctx_url['accept_ranges'] == 'bytes']
        else:
            urls = list(ctx_file_urls.keys())

        # Round Robin scheduling
        while True:
            for url in urls:
                ctx_url = ctx_file_urls[url]
                ctx_url['refcnt'] += 1
                yield [url]

                while ctx_url['refcnt'] % STRIPE_WIDTH:
                    ctx_url['refcnt'] += 1
                    yield [url]

    def _get_alt_urls(self, path_name):
        """Get alternative URLs from the multiple sources of the file to resume downloading from.

        Args:
            path_name (str): The full path name of the file to be downloaded.

        Returns:
            list: The alternative source URLs sorted by descending succeeded downloads, then by ascending interrupted
            and references.
        """
        ctx_file_urls = self._dl_ctx['files'][path_name]['urls']
        if self._is_download_resumable(path_name):
            url_ctxs = [(url, ctx_url['succeeded'], ctx_url['interrupted'], ctx_url['refcnt'])
                        for url, ctx_url in ctx_file_urls.items() if ctx_url['accept_ranges'] == 'bytes']
        else:
            url_ctxs = [(url, ctx_url['succeeded'], ctx_url['interrupted'], ctx_url['refcnt'])
                        for url, ctx_url in ctx_file_urls.items()]

        url_ctxs_sorted = sorted(url_ctxs, key=itemgetter(1, 2, 3))

        return [url_ctx[0] for url_ctx in url_ctxs_sorted]

    @staticmethod
    def _get_fname_from_hdr(content_disposition):
        """"Get the file name from the HTTP response header.

        Args:
            content_disposition (str): Content of the ``Content-Disposition`` field of the response header.

        Returns:
            str: The extracted file name.

        References:
            https://stackoverflow.com/questions/37060344
        """
        fname = re.findall(r"filename\*=([^;]+)", content_disposition, flags=re.IGNORECASE)
        if fname:
            if "utf-8''" in fname[0].lower():
                fname = re.sub("utf-8''", '', fname[0], flags=re.IGNORECASE)
                fname = unquote_unicode(fname)
            else:
                fname = fname[0]
        else:
            fname = re.findall("filename=([^;]+)", content_disposition, flags=re.IGNORECASE)
            if fname:
                fname = fname[0]

        fname = fname.strip().strip('"') if fname else ''

        return fname

    @staticmethod
    def _get_fname_from_url(url):
        """Generate a file name from the download URL.

        Args:
            url (str): A URL referencing the intended file.

        Returns:
            str: The automatically generated file name.
        """
        parsed = urlparse(url)
        unquoted_path = unquote_unicode(parsed.path)
        fname = os.path.basename(unquoted_path)
        if not fname:
            fn_path = '_'.join(unquoted_path.replace('/', ' ').split())
            fn_netloc = parsed.netloc.replace(':', '_')
            fname = fn_netloc + '-' + fn_path

        # limit the length of the filename to 250
        return fname[-250:].strip()

    @staticmethod
    def _topmost_missing_dir(path):
        """Find the topmost non-existent directory for a given path.

        Args:
            path (str): A path to the directory to save the downloaded file in.

        Returns:
            str: The uppermost directory that is missing from the `path`.
        """
        if not path or os.path.exists(path):
            return None

        path = os.path.abspath(path)
        drive, _ = os.path.splitdrive(path)
        drive_len = len(drive)
        last_missing = path
        while True:
            idx = path.rfind(os.sep)
            if idx <= drive_len:
                break

            parent_dir = path[:idx]
            if not os.path.exists(parent_dir):
                last_missing = parent_dir
                path = parent_dir
            else:
                break

        return last_missing

    def _rename_existing_file(self, full_pathname):
        """Rename the file or directory with the given pathname if present.

        Args:
            full_pathname (str): The full path name of the file to check for duplicate.
        """
        if not os.path.exists(full_pathname):
            return

        file_path, file_name = os.path.split(full_pathname)

        n = 2
        while True:
            new_name = "{}.({})".format(file_name, n)
            new_pathname = os.path.join(file_path, new_name)
            if not os.path.exists(new_pathname):  # neither regular file nor directory
                os.rename(full_pathname, new_pathname)
                self._logger.warning("The existed file '%s' has been renamed '%s'", full_pathname, new_pathname)

                break
            else:
                n += 1
                continue

    def _load_resumption_ctx(self, the_file, ctx_file):
        """Load from the resumption parts file to restore the download context.

        Args:
            the_file (str): The full path name of the file to download.
            ctx_file (dict): The download context of the file `the_file`.

        Returns:
            (bool, dict): A 2-tuple ``(is_resuming, resumption_ctx)``, where ``is_resuming`` indicates whether the
            download is resuming from last interruption, and if this is the case (``True``), ``resumption_ctx`` holds
            the successfully loaded resumption context.
        """
        is_resuming, resumption_ctx = False, None
        if not self.continuation or ctx_file['stdout']:
            return is_resuming, resumption_ctx

        file_inprocess = the_file + self.INPROCESS_EXT
        file_resumption = the_file + self.RESUM_PARTS_EXT

        if os.path.isfile(file_inprocess) and os.path.isfile(file_resumption):
            try:
                with open(file_resumption, "rb") as f:
                    resumption_ctx = pickle.load(f)

                is_resuming = True
                # verify that the loaded and newly obtained sizes match
                last_len, cur_len = resumption_ctx['length'], ctx_file['length']
                if last_len and cur_len and last_len != cur_len:  # This should not usually happen
                    is_resuming = False
                    self._logger.warning("The resumption of the download from interruption couldn't be accomplished"
                                         " due to the inconsistent file lengths, yet download will continue right "
                                         "from the start of the file: (new: '%r' -- old: '%r')",
                                         ctx_file['orig_path_url'], resumption_ctx['path_url'])
                    self._rename_existing_file(file_inprocess)
                    self._rename_existing_file(file_resumption)
            except Exception as e:
                self._logger.error("Error while loading the resumption parts info from '%s': '%s'", file_resumption, e)

        return is_resuming, resumption_ctx

    def _build_ctx_internal(self, path_name, url):
        """The helper method that actually does the build of the downloading context of the file.

        Args:
            path_name (str): The full path name of the file to download.
            url (str): The URL referencing the target file.

        Returns:
            tuple: A 3-tuple ``'(downloadable, (path, url), (orig_path, orig_url))'``, where the ``downloadable``
            indicates whether the desired file is downloadable, unavailable or existing by ``True``, ``False`` or
            ``None`` respectively, ``(path, url)`` denotes the converted full pathname and the URL that consists
            only of active URLs, and ``(orig_path, orig_url)`` denotes the originally input pathname and URL.

        Raises:
            :class:`BDownloaderException`: Raised when the termination or cancellation flag has been set.
        """
        path_url, orig_path_url = (path_name, url), (path_name, url)  # original `(path, url)`

        if not path_name:
            path_name = '.'
        if url is None:
            url = ''

        # Check whether `path_name` refers to a file (perhaps prefixed with a path) or a directory.
        # If it is a directory, then a file name should be determined through the `url`.
        path_head, path_tail = os.path.split(path_name)
        if not path_tail or os.path.isdir(path_name):
            file_name = ''
            file_path = path_name
        else:
            file_name = path_tail
            file_path = path_head

        is_stdout = path_name == self.STD_OUT  # whether the contents of the download should be written to standard output

        ctx_file = {'length': 0, 'progress': 0, 'last_progress': 0, 'downloaded': 0, 'stdout': is_stdout, 'resumable': False,
                    'resuming_from_intr': False, 'download_state': self.PENDING, 'cancelled_on_exception': False,
                    'orig_path_url': orig_path_url, 'path_url': None, 'urls': {}, 'ranges': {}, 'alt_ranges': [],
                    'worker_ranges': [], 'active_workers': 0, 'ranges_succeeded': 0}

        orig_urls = url.split()  # maybe whitespace-separated URLs
        active_urls = []
        downloadable = False  # Must have at least one active URL to download the file
        for mirror_url in orig_urls:
            # determine the URL-specific authentication
            auth = None
            parsed = urlparse(mirror_url)
            if parsed.username and parsed.password:
                auth = (parsed.username, parsed.password)
            elif self.netrc:
                auth = self.netrc.get(parsed.netloc)
                if not auth and parsed.port:
                    auth = self.netrc.get(parsed.hostname)
            if not auth:
                auth = self.auth

            auth_up = None if isinstance(auth, AuthBase) else auth  # ('user', 'passwd')
            auth_wx = auth if isinstance(auth, AuthBase) else None

            headers = {'Accept-Encoding': 'identity'}  # request for the actual size of the file
            try:
                with self.requester.get(mirror_url, headers=headers, allow_redirects=True, stream=True, auth=auth_wx) as r:
                    if r.status_code == requests.codes.unauthorized and auth_up:
                        r_auth = r.headers.get('www-authenticate', '').lower()
                        if "digest" in r_auth:
                            auth_wx = HTTPDigestAuth(*auth_up)
                            auth_wx.init_per_thread_state()
                            auth_wx._thread_local.num_401_calls = 0
                            r = auth_wx.handle_401(r)
                        elif "basic" in r_auth:
                            auth_wx = HTTPBasicAuthEx(*auth_up)
                            r = auth_wx.handle_401(r)

                    if r.status_code == requests.codes.ok:
                        file_len = int(r.headers.get('Content-Length', 0))
                        if file_len:
                            if not ctx_file['length']:
                                ctx_file['length'] = file_len
                            else:
                                if file_len != ctx_file['length']:
                                    self._logger.error("Error: the size of the file '%s' obtained from '%s' happened to "
                                                       "mismatch with that from others, download will continue but the "
                                                       "downloaded file may not be the intended one", file_name, mirror_url)

                                    continue

                        auth_header = {'Authorization': r.request.headers['Authorization']} if r.request.headers.get('Authorization') else {}
                        ctx_url = ctx_file['urls'][mirror_url] = {'auth': auth_wx, 'auth_header': auth_header,
                                                                  'accept_ranges': "none", 'refcnt': 0, 'interrupted': 0,
                                                                  'succeeded': 0}

                        accept_ranges = r.headers.get('Accept-Ranges')
                        if "bytes" == accept_ranges:
                            ctx_url['accept_ranges'] = accept_ranges
                            ctx_file['resumable'] = True

                        if not file_name:
                            content_disposition = r.headers.get('Content-Disposition')
                            if content_disposition:
                                file_name = self._get_fname_from_hdr(content_disposition)

                        downloadable = True
                        active_urls.append(mirror_url)
                    else:
                        self._logger.warning("Unexpected status code %d: trying to determine the size of the file '%s' "
                                             "using '%s'", r.status_code, file_name, mirror_url)
            except requests.RequestException as e:
                self._logger.error("Error while trying to determine the size of the file '%s' using '%s': '%r'",
                                   file_name, mirror_url, e)

        if downloadable:
            if not file_name:
                file_name = self._get_fname_from_url(active_urls[0])

            file_path_name = os.path.abspath(os.path.join(file_path, file_name)) if not is_stdout else self.STD_OUT
            path_url = (file_path_name, '\t'.join(active_urls))

            # save the full pathname and active URLs. cf. 'orig_path_url'
            ctx_file['path_url'] = path_url

            # check for conflicting `file_path_name` in downloading jobs
            if file_path_name in self._dl_ctx['files']:
                dup_orig_path_url = self._dl_ctx['files'][file_path_name]['orig_path_url']
                self._logger.error("Full path name conflicting error: '%s'. Intended: '%r';already in downloading: '%r'",
                                   file_path_name, orig_path_url, dup_orig_path_url)

                return False, path_url, orig_path_url

            is_resuming, resumption_ctx = self._load_resumption_ctx(file_path_name, ctx_file)
            ctx_file['resuming_from_intr'] = is_resuming
            ctx_file['progress'] = ctx_file['last_progress'] = resumption_ctx['progress'] if is_resuming else 0

            # check whether the desired file already exists or not
            if self.continuation and not is_resuming and not is_stdout and os.path.isfile(file_path_name):
                file_len = os.stat(file_path_name).st_size
                if ctx_file['length'] and file_len == ctx_file['length']:
                    self._logger.warning("The desired file '%s' already exists out there, so that there is no need to "
                                         "re-download it: '%r'", file_path_name, ctx_file['orig_path_url'])

                    ctx_file['download_state'] = self.SUCCEEDED
                    self._dl_ctx['files'][file_path_name] = ctx_file
                    self._dl_ctx['total_size'] += ctx_file['length']
                    self._dl_ctx['last_progress'] += ctx_file['length']

                    return None, path_url, orig_path_url
                else:
                    self._logger.warning("A file with the desired name '%s' has been detected, but its size cannot be "
                                         "validated, so the download will start anew, and the existing file will be "
                                         "renamed on completion: '%r'", file_path_name, ctx_file['orig_path_url'])

            if not is_resuming and not is_stdout:
                # Prepare the necessary directory structure and file template
                file_inprocess = file_path_name + self.INPROCESS_EXT
                top_missing_dir = self._topmost_missing_dir(file_path)
                try:
                    if top_missing_dir:
                        mkpath(file_path)

                    with open(file_inprocess, mode='w') as _:
                        pass
                except (EnvironmentError, DistutilsFileError) as e:
                    self._logger.error("Error while operating on '%s': '%s'; Try downloading: '%r'", file_inprocess, e,
                                       orig_path_url)

                    if top_missing_dir:
                        try:
                            remove_tree(top_missing_dir)
                        except Exception:
                            pass

                    return False, path_url, orig_path_url

            # Add the file to the list ready to download
            self._dl_ctx['files'][file_path_name] = ctx_file

            self._dl_ctx['total_size'] += ctx_file['length']
            if not ctx_file['length']:
                self._dl_ctx['accurate'] = False
                self._logger.warning("The size of the file '%s' couldn't be determined: '%r'", file_path_name, ctx_file['orig_path_url'])

            iter_url = self._pick_file_url(file_path_name)

            if not is_resuming:
                # calculate request ranges
                if self._is_parallel_downloadable(file_path_name) and self.workers_per_download > 1:
                    ranges = self.calc_req_ranges(ctx_file['length'], self.min_split_size, 0)
                else:
                    ranges = [(0, None)]

                for start, end in ranges:
                    req_range = "bytes={}-{}".format(start, end)
                    ctx_range = ctx_file['ranges'][req_range] = {}
                    ctx_range.update({
                        'start': start,
                        'end': end,
                        'offset': 0,
                        'last_offset': 0,
                        'start_time': 0,
                        'rt_dl_speed': 0,
                        'download_state': self.PENDING,
                        'url': next(iter_url),
                        'alt_urls': {}})
            else:
                ctx_file['ranges'] = resumption_ctx['failed_ranges']

                for ctx_range in ctx_file['ranges'].values():
                    ctx_range['url'] = next(iter_url)
                    ctx_range['alt_urls'] = {}

            ctx_file['alt_ranges'] = [(req_range, ctx_range) for req_range, ctx_range in ctx_file['ranges'].items()]
            ctx_file['alt_ranges'].reverse()  # To pop from the range stack and download from the beginning of the file

            # make the file visible to the world
            self._dl_ctx['alt_files'].append((file_path_name, ctx_file))
            self._dl_ctx['file_cnt'] += 1
            self._dl_ctx['last_progress'] += ctx_file['last_progress']

        return downloadable, path_url, orig_path_url

    def _build_ctx(self, path_urls):
        """Build the context for downloading the file(s).

        Args:
            path_urls (list of tuple): Paths and URLs for the file(s) to download, see :meth:`downloads` for details.

        Returns:
            A 6-tuple of lists ``'(active, active_orig, failed, failed_orig, existing, existing_orig)'``, where the
            :obj:`list`\ s ``active`` and ``active_orig`` contain the active ``(path, url)``'s, converted and original
            respectively; ``failed`` and ``failed_orig`` contain the same ``(path, url)``'s that are not downloadable;
            ``existing`` and ``existing_orig`` contain the downloads whose desired files already exist out there.

        Raises:
            :class:`BDownloaderException`: Raised when the termination or cancellation flag has been set.
        """
        active, active_orig = [], []
        failed, failed_orig = [], []
        existing, existing_orig = [], []
        for path_name, url in path_urls:
            downloadable, path_url, orig_path_url = self._build_ctx_internal(path_name, url)
            if downloadable:
                active.append(path_url)
                active_orig.append(orig_path_url)
            elif downloadable is None:
                existing.append(path_url)
                existing_orig.append(orig_path_url)
            else:
                failed.append(path_url)
                failed_orig.append(orig_path_url)

        return active, active_orig, failed, failed_orig, existing, existing_orig

    def _is_all_done(self):
        """Check if all the tasks have completed.

        Returns:
            bool: ``True`` if all the ``Future``\ s have been done, meaning that all the files have finished downloading,
            whether successfully or not; ``False`` otherwise.
        """
        return self.all_submitted and self._dl_ctx['file_cnt'] == (
                    len(self.succeeded_downloads_in_running) + len(self.failed_downloads_in_running))

    def _backup_resumption_ctx(self, the_file, ctx_file):
        """Back up the necessary context of the unsuccessful download for resuming later.

        Args:
            the_file (str): The full path name of the file being downloaded.
            ctx_file (dict): The download context of the file `the_file`.

        Returns:
            dict: The resumption context for the file `the_file`.
        """
        ctx = {
            'file_name': os.path.basename(the_file),
            'path_url': ctx_file['orig_path_url'],
            'length': ctx_file['length'],
            'progress': ctx_file['progress'],  # successfully downloaded bytes in this run
            'failed_ranges': {}  # ranges with a state in `_RANGE_STATES` except `SUCCEEDED`
        }

        for req_range, ctx_range in ctx_file['ranges'].items():
            if ctx_range['download_state'] != self.SUCCEEDED:
                crange = ctx['failed_ranges'][req_range] = {}
                crange.update({
                    'start': ctx_range['start'],
                    'end': ctx_range['end'],
                    'offset': ctx_range['offset'],
                    'last_offset': 0,
                    'start_time': 0,
                    'rt_dl_speed': 0,
                    'download_state': self.PENDING
                })

        return ctx

    def _on_succeeded(self, the_file, ctx_file):
        """When transitioning to the `SUCCEEDED` state, convert from in-process to finished file and do the cleanup."""
        if ctx_file['stdout']:
            return

        file_inprocess = the_file + self.INPROCESS_EXT
        file_resumption = the_file + self.RESUM_PARTS_EXT

        try:
            self._rename_existing_file(the_file)  # rename the existing conflicting file if present
            os.rename(file_inprocess, the_file)

            # delete the download progress file (i.e. `*.bdl.par` for resumption parts info) if present
            if os.path.isfile(file_resumption):
                os.remove(file_resumption)

            self._logger.info("The download of the file '%s' has succeeded: '%r'", the_file, ctx_file['orig_path_url'])
        except EnvironmentError as e:
            self._logger.error("Error while operating on '%s': 'Error number %d: %s'", e.filename, e.errno, e.strerror)

    def _on_failed(self, the_file, ctx_file):
        """When transitioning to the `FAILED` state, save the resumption ctx or remove the intermediate files."""
        if ctx_file['stdout']:
            return

        file_inprocess = the_file + self.INPROCESS_EXT
        file_resumption = the_file + self.RESUM_PARTS_EXT

        try:
            if self.continuation and ctx_file['resumable']:
                with open(file_resumption, "wb") as fd:
                    pickle.dump(self._backup_resumption_ctx(the_file, ctx_file), fd, PICKLE_PROTOCOL_NUMBER)

                self._logger.warning("The download of the file '%s' has failed, but can be resumed by re-running it: "
                                     "'%r'", the_file, ctx_file['orig_path_url'])
            else:
                os.remove(file_inprocess)
                # delete the download progress file (i.e. `*.bdl.par` for resumption parts info) if present
                if os.path.isfile(file_resumption):
                    os.remove(file_resumption)

                self._logger.warning("The download of the file '%s' has failed, and can't be resumed either because "
                                     "the resumption feature is intentionally disabled or because the URLs don't "
                                     "support this; Accordingly, the broken file(s) has been removed: '%r'", the_file,
                                     ctx_file['orig_path_url'])
        except EnvironmentError as e:
            self._logger.error("Error while operating on '%s': 'Error number %d: %s'", e.filename, e.errno, e.strerror)
        except pickle.PicklingError as e:
            self._logger.error("Error while dumping the resumption context into '%s': '%r'", file_resumption, e)

    def _on_cancelled(self, the_file, ctx_file):
        """When transitioning to the `CANCELLED` state, remove the empty, obsolete files."""
        if ctx_file['stdout']:
            return

        file_inprocess = the_file + self.INPROCESS_EXT
        file_resumption = the_file + self.RESUM_PARTS_EXT

        try:
            if not ctx_file['resuming_from_intr']:
                os.remove(file_inprocess)
                # delete the download progress file (i.e. `*.bdl.par` for resumption parts info) if present
                if os.path.isfile(file_resumption):
                    os.remove(file_resumption)

                self._logger.info("The download of the file '%s' has been cancelled on demand, and the broken file(s) "
                                  "have been removed accordingly: '%r'", the_file, ctx_file['orig_path_url'])
            else:
                self._logger.warning("The download of the file '%s' has been cancelled on demand, but can be resumed "
                                     "by re-running it: '%r'", the_file, ctx_file['orig_path_url'])
        except EnvironmentError as e:
            self._logger.error("Error while operating on '%s': 'Error number %d: %s'", e.filename, e.errno, e.strerror)

    def _cancel_all_on_interrupted(self):
        """Cancel all the pending tasks when receiving the ``SIGINT`` signal or the QUIT command."""
        if self.all_submitted and not self.cancelled_on_interrupt:
            for fi in range(self._dl_ctx['next_download'], self._dl_ctx['file_cnt']):
                the_file, ctx_file = self._dl_ctx['alt_files'][fi]
                ctx_file['download_state'] = self.CANCELLED
                self._on_cancelled(the_file, ctx_file)
                self.failed_downloads_in_running.append(ctx_file['orig_path_url'])

            self.cancelled_on_interrupt = True
            self._logger.warning("The user terminated the downloads %s!",
                                 "by pressing the interrupt key" if self.sigint else "by typing the QUIT command")

    def _finalize_on_interrupted_py2(self):
        """When interrupted under Python2.x, perform state transitions manually and act accordingly."""
        for the_file, ctx_file in self._dl_ctx['files'].items():
            if ctx_file['download_state'] == self.INPROCESS:
                self._on_failed(the_file, ctx_file)
            elif ctx_file['download_state'] == self.PENDING:
                self._on_cancelled(the_file, ctx_file)

    def _schedule_dl_tasks(self, path_name, num_tasks):
        """Arrange the range downloading tasks of the file and assign them to the thread pool executor.

        Args:
            path_name (str): The full path name of the file being scheduled for.
            num_tasks (int): The number of the range tasks requested to allocate.

        Returns:
            list of tuple: The (re-)scheduled range tasks and their corresponding download contexts.
        """
        worker_ranges = []
        ctx_file = self._dl_ctx['files'][path_name]

        if len(ctx_file['ranges']) > 1:
            tsk = self._get_remote_file_multipart
        else:
            tsk = self._get_remote_file_singlewhole

        while ctx_file['alt_ranges'] and len(worker_ranges) < num_tasks:
            req_range, ctx_range = ctx_file['alt_ranges'].pop()
            future = self.executor.submit(tsk, path_name, req_range)
            ctx_range['future'] = future
            ctx_range['start_time'] = time.time()

            worker_ranges.append((req_range, ctx_range))

        return worker_ranges

    def _schedule_files_downloads(self):
        """Remove the completed tasks from the files downloading queue and submit new file task assignments."""
        active_files = []

        for the_file, ctx_file in self._dl_ctx['active_files']:
            if ctx_file['download_state'] not in self._COMPLETED:
                active_files.append((the_file, ctx_file))
            else:
                self._dl_ctx['active_downloads'] -= 1

        while self._dl_ctx['active_downloads'] < self.max_parallel_downloads and self._dl_ctx['next_download'] < self._dl_ctx['file_cnt']:
            the_file, ctx_file = self._dl_ctx['alt_files'][self._dl_ctx['next_download']]
            ctx_file['worker_ranges'] = self._schedule_dl_tasks(the_file, self.workers_per_download)
            ctx_file['active_workers'] = len(ctx_file['worker_ranges'])

            active_files.append((the_file, ctx_file))
            self._dl_ctx['active_downloads'] += 1
            self._dl_ctx['next_download'] += 1

        self._dl_ctx['active_files'] = active_files

    def _schedule_file_download(self, the_file, ctx_file):
        """Remove the succeeded range tasks, reassign the failed and arrange new for the file downloading."""
        worker_ranges, raised_ranges = [], []

        for req_range, ctx_range in ctx_file['worker_ranges']:
            if ctx_range['download_state'] not in self._COMPLETED:
                worker_ranges.append((req_range, ctx_range))
            elif ctx_range['download_state'] == self.FAILED:
                ctx_range['download_state'] = self.PENDING
                ctx_range['future'] = None
                ctx_range['last_offset'] = ctx_range['offset']
                raised_ranges.append((req_range, ctx_range))

        ctx_file['alt_ranges'] += raised_ranges

        worker_ranges += self._schedule_dl_tasks(the_file, ctx_file['active_workers'] - len(worker_ranges))
        ctx_file['worker_ranges'] = worker_ranges

    def _state_mgmnt(self):
        """Perform the state-related operations of file downloading.

        This method updates the download status of the files and their related chunks when the associated worker threads
        completed, either because of finished without error, raised on exception or cancelled intentionally.

        Returns:
            None.
        """
        if not (self.sigint or self.cmdquit):
            # Assign new file-level downloads and submit their initial range tasks to the thread pool when current downloads' state changed
            if self._dl_ctx['poll_changed'] or (self._dl_ctx['active_downloads'] < self.max_parallel_downloads and
                                                self._dl_ctx['next_download'] < self._dl_ctx['file_cnt']):
                self._schedule_files_downloads()
                self._dl_ctx['poll_changed'] = False
        else:
            # Cancel the pending tasks on the downloading queue when interrupted
            self._cancel_all_on_interrupted()

        for the_file, ctx_file in self._dl_ctx['active_files']:
            ranges_have_dones = False

            for _, ctx_range in ctx_file['worker_ranges']:
                future = ctx_range['future']
                if future.done():
                    ranges_have_dones = True
                    ctx_file['downloaded'] += ctx_range['offset'] - ctx_range['last_offset']
                    self._dl_ctx['downloaded'] += ctx_range['offset'] - ctx_range['last_offset']

                    try:
                        exception = future.exception()
                        if exception is None:
                            ctx_range['download_state'] = self.SUCCEEDED
                            ctx_file['ranges_succeeded'] += 1
                            ctx_file['progress'] += ctx_range['offset']

                            # Accumulate the download statistics of the source URLs
                            for url, ctx_url_range in ctx_range['alt_urls'].items():
                                ctx_url_file = ctx_file['urls'][url]
                                ctx_url_file['refcnt'] += ctx_url_range.get('refcnt', 0)
                                ctx_url_file['interrupted'] += ctx_url_range.get('interrupted', 0)
                            # use MINUS for ease of multi-level sorting
                            ctx_file['urls'][ctx_range['url'][-1]]['succeeded'] -= 1
                        else:  # exception raised
                            ctx_range['download_state'] = self.FAILED
                            ctx_file['active_workers'] -= 1
                    except CancelledError:
                        # could not reach here
                        ctx_range['download_state'] = self.CANCELLED

            if ctx_file['ranges_succeeded'] == len(ctx_file['ranges']):
                ctx_file['download_state'] = self.SUCCEEDED
                self._dl_ctx['poll_changed'] = True

                self.succeeded_downloads_in_running.append(ctx_file['orig_path_url'])
                self._on_succeeded(the_file, ctx_file)
            elif ctx_file['active_workers'] == 0:
                ctx_file['download_state'] = self.FAILED
                self._dl_ctx['poll_changed'] = True

                self.failed_downloads_in_running.append(ctx_file['orig_path_url'])
                self._on_failed(the_file, ctx_file)
            elif ranges_have_dones:
                self._schedule_file_download(the_file, ctx_file)

    def _mgmnt_task(self):
        """The management thread body.

        This thread manages the downloading process of the whole job queue, currently including state management only.
        When all the tasks have been done, it signals the waiting thread and exits immediately.

        Returns:
            None.
        """
        while not self.all_done:
            self._state_mgmnt()

            if self._is_all_done():
                self.all_done = True
                self.all_done_event.set()

                continue

            time.sleep(0.1)

    def _calc_completed(self):
        """Calculate the already downloaded bytes of the files.

        Returns:
            int: The size in bytes of the downloaded pieces.
        """
        completed = self._dl_ctx['last_progress']
        for fi in range(self._dl_ctx['next_download']):
            _, ctx_file = self._dl_ctx['alt_files'][fi]
            if ctx_file['download_state'] not in self._COMPLETED:
                ctx_ranges = ctx_file.get('ranges')
                if ctx_ranges:
                    for ctx_range in ctx_ranges.values():
                        completed += ctx_range.get('offset', 0)
            else:
                completed += ctx_file['downloaded']

        return completed

    def _progress_task(self):
        """The thread body for showing the progress of the downloading tasks.

        Returns:
            None.
        """
        dl_acc_changed = False  # Added unknown-sized downloads?
        acc_label = 'Dl/Expect:'
        inacc_label = 'Dl/Expect(approx.):'

        progress_bar = MillProgress(label=acc_label, every=1024) if self.progress == self.PROGRESS_BS_MILL else clint_progress.Bar()

        while not self.stop:
            if not self._dl_ctx['accurate'] and not dl_acc_changed:
                if self.progress != self.PROGRESS_BS_MILL:
                    progress_bar = MillProgress(every=1024)

                    self._logger.info("The progress bar has been changed to a mill due to unknown-sized download(s)")

                progress_bar.label = inacc_label
                dl_acc_changed = True

            progress_bar.show(self._calc_completed(), count=self._dl_ctx['total_size'])

            time.sleep(0.1)
        else:
            progress_bar.last_progress = self._dl_ctx['last_progress'] + self._dl_ctx['downloaded']
            progress_bar.expected_size = self._dl_ctx['total_size']
            progress_bar.done()

    def progress_all(self):
        """Get the coarse-grained, overall progress of the downloads.

        Returns:
            tuple: The 3-tuple of the form ``(completed_bytes, total_bytes, is_accurate)``. ``completed_bytes`` is updated
            on a chunk basis from the worker threads by the management task. If ``is_accurate`` is `False` then ``total_bytes``
            is inaccurate, i.e. some downloads have undetermined sizes, which also means ``completed_bytes`` may be greater
            than the ``total_bytes``; otherwise, ``total_bytes`` is the exact sum of sizes of all the downloads. Note that
            ``total_bytes`` (and ``is_accurate``) may vary during the phase of submitting the downloads.
        """
        return self._dl_ctx['last_progress'] + self._dl_ctx['downloaded'], self._dl_ctx['total_size'], self._dl_ctx['accurate']

    def downloads(self, path_urls):
        """Submit multiple downloading jobs at a time to the downloading queue.

        Args:
            path_urls (:obj:`list` of :obj:`tuple`\ s): `path_urls` accepts a list of tuples of the form ``(path, url)``,
                where ``path`` should be a pathname, optionally prefixed with absolute or relative paths, and ``url`` should
                be a URL string, which may consist of multiple TAB-separated URLs pointing to the same file.
                Note that a single dash '-' specifies the ``path`` reserved for the standard output.
                A valid `path_urls`, for example, could be [('/opt/files/bar.tar.bz2', ``'https://foo.cc/bar.tar.bz2'``),
                ('./sanguoshuowen.pdf', ``'https://bar.cc/sanguoshuowen.pdf\\thttps://foo.cc/sanguoshuowen.pdf'``),
                ('/**to**/**be**/created/', ``'https://flash.jiefang.rmy/lc-cl/gaozhuang/chelsia/rockspeaker.tar.gz'``),
                ('/path/to/**existing**-dir', ``'https://ghosthat.bar/foo/puretonecone81.xz\\thttps://tpot.horn/foo/pure
                tonecone81.xz\\thttps://hawkhill.bar/foo/puretonecone81.xz'``)].

        Returns:
            None.

        Raises:
            :class:`BDownloaderException`: Raised when the downloads were interrupted, e.g. by calling :meth:`cancel`
                in a ``SIGINT`` signal handler, in the process of submitting the download requests.

        Notes:
            The method is not thread-safe, which means it should not be called at the same time in multiple threads
            with one instance.

            When multi-instanced (e.g. one instance per thread), the file paths specified in one instance should not
            overlap those in another to avoid potential race conditions. File loss may occur, for example, if a failed
            download task in one instance tries to delete a directory that is being accessed by some download tasks in
            other instances.
            However, this limitation doesn't apply to the file paths specified in a same instance.
        """
        self._dl_ctx['orig_path_urls'].extend(path_urls)

        for chunk_path_urls in self.list_split(path_urls, chunk_size=2):
            active, active_orig, _, failed_orig, _, existing_orig = self._build_ctx(chunk_path_urls)
            if active:
                if self.progress != self.PROGRESS_BS_NONE and self.progress_thread is None:
                    self.progress_thread = threading.Thread(target=self._progress_task)
                    self.progress_thread.start()

                if self.mgmnt_thread is None:
                    self.mgmnt_thread = threading.Thread(target=self._mgmnt_task)
                    self.mgmnt_thread.start()

                self.active_downloads_added.extend(active_orig)

            if existing_orig:
                self.succeeded_downloads_on_addition.extend(existing_orig)

            if failed_orig:
                self.failed_downloads_on_addition.extend(failed_orig)

    def download(self, path_name, url):
        """Submit a single downloading job to the downloading queue.

        This method is simply a wrapper of the method :meth:`downloads`.

        Args:
            path_name (str): The full path name of the file to be downloaded.
            url (str): The URL referencing the target file.

        Returns:
            None.

        Raises:
            :class:`BDownloaderException`: Same as in :meth:`downloads`.

        Notes:
            The limitation on the method and the `path_name` parameter herein is the same as in :meth:`downloads`.
        """
        return self.downloads([(path_name, url)])

    def _result(self):
        """"Return both the succeeded and failed downloads when all done or interrupted by user.

        Returns:
            tuple of list: Same as that returned by :meth:`wait_for_all`.
        """
        succeeded = self.succeeded_downloads_in_running + self.succeeded_downloads_on_addition
        failed = [path_url for path_url in self._dl_ctx['orig_path_urls'] if path_url not in succeeded]

        return succeeded, failed

    def _wait_py3(self):
        """Wait for all the jobs done on Python 3.x and newer"""
        while not self.all_done:
            self.all_done_event.wait(self._INTERRUPTIBLE_WAIT_TIMEOUT)

    def _wait_py2(self):
        """Wait for all the jobs done on Python 2.x"""
        while not self.all_done:
            if not self.sigint:
                self.all_done_event.wait(self._INTERRUPTIBLE_WAIT_TIMEOUT)
            else:
                # https://github.com/agronholm/pythonfutures/issues/25
                self.all_done_event.wait(self._PY2_SIGINT_WAIT_TIMEOUT)
                break

    def wait_for_all(self):
        """Wait for all the downloading jobs to complete.

        Returns:
            tuple of list: A 2-tuple of lists ``'(succeeded, failed)'``. The first list ``succeeded`` contains the
            originally passed ``(path, url)``\ s that finished successfully, while the second list ``failed`` contains
            the raised and cancelled ones.
        """
        self.all_submitted = True

        if not self.all_done and self.mgmnt_thread and self.mgmnt_thread.is_alive():
            wait4all = self._wait_py3 if _py3plus else self._wait_py2
            wait4all()

        succeeded, failed = self._result()
        if self.sigint and not _py3plus:
            self._logger.warning('The download was interrupted by the user: '
                                 '"succeeded in downloading: %r; failed to download: %r"', succeeded, failed)

        return succeeded, failed

    def results(self):
        """Get both the succeeded and failed downloads when all done or interrupted by user.

        Returns:
            tuple of list: Same as that returned by :meth:`wait_for_all`.
        """
        if not self.all_done:
            return self.wait_for_all()

        return self._result()

    def result(self):
        """Return the final download status.

        Returns:
            int: 0 for success, and -1 failure.
        """
        if not self.all_done:
            self.wait_for_all()

        added = len(self._dl_ctx['orig_path_urls'])
        succeeded = len(self.succeeded_downloads_on_addition) + len(self.succeeded_downloads_in_running)

        return 0 if not (self.sigint or self.cmdquit) and added and added == succeeded else -1

    def cancel(self, keyboard_interrupt=True):
        """Cancel all the download jobs.

        Args:
            keyboard_interrupt (bool): Specifies whether or not the user hit the interrupt key (e.g. Ctrl-C).

        Returns:
            None.
        """
        if keyboard_interrupt:
            self.sigint = True
        else:
            self.cmdquit = True

    def close(self):
        """Shut down and perform the cleanup.

        Returns:
            None.
        """
        if not self.all_done:
            self.wait_for_all()

        # actual `close` starts here
        self.stop = True

        if self.sigint and not _py3plus:
            timeout = self._PY2_SIGINT_JOIN_TIMEOUT
            shutdown = _os_exit_force  # non-gracefully shutdown on Python 2.x when interrupted

            self._finalize_on_interrupted_py2()

            # flush stdio buffers before forcibly shutting down
            sys.stdout.flush()
            sys.stderr.flush()
        else:
            timeout = None
            shutdown = self.executor.shutdown

        if self.progress_thread is not None:
            self.progress_thread.join(timeout)

        if self.mgmnt_thread is not None:
            self.mgmnt_thread.join(timeout)

        shutdown()


class BDownloaderException(Exception):
    """The exception indicating that an error occurred while executing the download tasks."""
    pass
