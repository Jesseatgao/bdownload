from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import time
import random
from functools import wraps
import logging
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor, CancelledError  # ,wait
from math import trunc
import re

try:
    from urllib.parse import unquote, urlparse

    unichr = chr
except ImportError:
    from urllib import unquote
    from urlparse import urlparse

from distutils.dir_util import mkpath
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests import Session
from clint.textui import progress


here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, 'VERSION'), mode='r') as fd:
    __version__ = fd.read().strip()

# retry configuration

#: int: Number of retries on exception wrapping around the ``requests.Session``'s methods.
REQUESTS_RETRIES_ON_METHOD_EXCEPTION = 3

#: int: Number of retries on exception set through ``urllib3``'s `Retry` mechanism.
URLLIB3_RETRIES_ON_EXCEPTION = 3

#: int: Number of retries on exceptions raised while streaming the request content.
REQUESTS_RETRIES_ON_STREAM_EXCEPTION = 10

#: float: Default retry backoff factor.
RETRY_BACKOFF_FACTOR = 0.1

#: set: Default status codes to retry on intended for the underlying ``urllib3``.
URLLIB3_RETRY_STATUS_CODES = frozenset([413, 429, 500, 502, 503, 504])


def retry_requests(exceptions, retries=3, backoff_factor=0.1, logger=None):
    """A decorator that retries calling the wrapped ``requests``' function using an exponential backoff on exception.

    The retry attempt will be activated in the event of `exceptions` being caught and for all the bad status codes (i.e.
    codes ranging from 400 to 600).

    Args:
        exceptions (:obj:`Exception` or :obj:`tuple` of :obj:`Exception`\ s): The exceptions to check against.
        retries (int): Number of retries when `exceptions` occurred.
        backoff_factor (float): The backoff factor to apply between retries.
        logger (logging.Logger): An event logger.

    Returns:
        The wrapper function.

    Raises:
        `exceptions`: Re-raise the last caught exception when retries is exhausted.

    References:
         http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
         https://en.wikipedia.org/wiki/Exponential_backoff
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    def deco_retry(f):

        @wraps(f)
        def f_retry(*args, **kwargs):
            ntries = 0
            while True:
                try:
                    r = f(*args, **kwargs)  # `r` is an instance of the ``requests.Response`` object
                    r.raise_for_status()
                    return r
                except exceptions as e:
                    ntries += 1
                    if ntries > retries:
                        raise e
                    steps = random.randrange(1, 2**ntries)
                    backoff = steps * backoff_factor

                    logger.warning('{!r}, Retrying {}/{} in {:.2f} seconds...'.format(e, ntries, retries, backoff))

                    time.sleep(backoff)

        return f_retry  # true decorator

    return deco_retry


class RequestsSessionWrapper(Session):
    """Subclass of the ``requests``' ``Session`` class with extended `retry-on-exception` behavior for the `get` method.

    Note:
        The retry mechanism here is independent from that of from ``urllib3`` (see :func:`requests_retry_session`).
        Nevertheless, they together determine the number of the total retries using the following formula:

        (:const:`REQUESTS_RETRIES_ON_METHOD_EXCEPTION` + 1) * (`retries` passed to :func:`requests_retry_session`).
    """
    def __init__(self):
        """Initialize the `Session` explicitly.
        """
        super(RequestsSessionWrapper, self).__init__()

    @retry_requests(requests.RequestException,
                    retries=REQUESTS_RETRIES_ON_METHOD_EXCEPTION, backoff_factor=RETRY_BACKOFF_FACTOR)
    def get(self, url, timeout=(3.05, 6), **kwargs):
        """Wrapper around ``requests.Session``'s `get` method decorated with the :func:`retry_requests` decorator.

        Args:
            url: URL for the file to download from.
            timeout (2-tuple of int): Timeout values for both the ``connect`` and the ``read`` timeouts, respectively.
                The ``connect`` timeout value defaults to 3.05 seconds, and the ``read`` timeout to 6 seconds.
            **kwargs: Same arguments as that ``requests.Session.get`` takes.

        Returns:
            ``requests.Response``: The response to the HTTP ``GET`` request.
        """
        return super(RequestsSessionWrapper, self).get(url, timeout=timeout, **kwargs)


def requests_retry_session(retries=3, backoff_factor=0.1, status_forcelist=None,
                           session=None, num_pools=20, pool_maxsize=20):
    """Create a session object of the class :class:`RequestsSessionWrapper` by default.

    Aside from the retry mechanism implemented by the wrapper decorator, the created session also leverages the built-in
    retries bound to ``urllib3``. For how they cooperate to determine the total retries, see :class:`RequestsSessionWrapper`.

    The HTTP header ``User-Agent`` of the session is set to a default value of `bdownload/VERSION`, with `VERSION` being
    replaced by the package's version number.

    Args:
        retries (int): Maximum number of retry attempts allowed on errors and interested status codes, which will apply
            to the retry logic of the underlying ``urllib3``.
        backoff_factor (float): The backoff factor to apply between retries.
        status_forcelist (set of int): A set of HTTP status codes that a retry should be enforced on. The default status
            forcelist shall be :const:`URLLIB3_RETRY_STATUS_CODES` if not given.
        session (:obj:`requests.Session`): An instance of the class ``requests.Session`` or its customized subclass.
            When not provided, it will use :class:`RequestsSessionWrapper` to create by default.
        num_pools (int): The number of connection pools to cache, which has the same meaning as `num_pools` in
            ``urllib3.PoolManager`` and will eventually be passed to it.
        pool_maxsize (int): The maximum number of connections to save that can be reused in the ``urllib3`` connection
            pool, which will be passed to the underlying ``requests.adapters.HTTPAdapter``.

    Returns:
        ``requests.Session``: The session instance with retry capability.

    References:
         https://www.peterbe.com/plog/best-practice-with-retries-with-requests
    """
    session = session or RequestsSessionWrapper()
    status_forcelist = status_forcelist or URLLIB3_RETRY_STATUS_CODES

    # Initialize the session with default HTTP headers
    default_user_agent = 'bdownload/{}'.format(__version__)
    headers = {
        'User-Agent': default_user_agent,
    }
    session.headers = headers

    # Initialize the built-in retry mechanism and the connection pools
    max_retries = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=max_retries, pool_connections=num_pools, pool_maxsize=pool_maxsize, pool_block=True)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    return session


def _build_cookiejar_from_kvp(key_values):
    """Build a CookieJar from cookies in the form of key/value pairs.

    Args:
        key_values (str): The cookies must take the form of ``'cookie_key=cookie_value'``, with multiple pairs separated
            by space character if applicable, e.g. ``'key1=val1 key2=val2'``.

    Returns:
        ``requests.cookies.RequestsCookieJar``: The built CookieJar for ``requests`` sessions.
    """
    if key_values:
        cookiejar = requests.cookies.RequestsCookieJar()
        kvps = key_values.split()
        for kvp in kvps:
            key, value = kvp.split("=")
            cookiejar.set(key, value)

        return cookiejar


def unquote_unicode(string):
    """Unquote a percent-encoded string.

    Args:
        string (str): A %xx and %uxxxx -encoded string.

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
    MILL_TEMPLATE = '{}  {}  {:,d}/{:<}  {}  {:>}: {}\r'
    MILL_CHARS = ['|', '/', '-', '\\']

    # How long to wait before recalculating the ETA
    ETA_INTERVAL = 1
    # How many intervals (excluding the current one) to calculate the simple moving average
    ETA_SMA_WINDOW = 9

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.done()
        return False

    def __init__(self, label='', hide=None, expected_size=None, every=1):
        self.label = label
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

    def format_time(self, seconds):
        return time.strftime('%H:%M:%S', time.gmtime(seconds))

    def mill_char(self, progress):
        # if self.expected_size and progress >= self.expected_size:
        #     return ' '
        # else:
        #     return self.MILL_CHARS[(progress // self.every) % len(self.MILL_CHARS)]
        return self.MILL_CHARS[(progress // self.every) % len(self.MILL_CHARS)]

    def show(self, progress, count=None):
        if count is not None:
            self.expected_size = count

        self.last_progress = progress

        if self.expected_size:
            if progress <= self.expected_size:
                if (time.time() - self.etadelta) > self.ETA_INTERVAL:
                    self.etadelta = time.time()
                    self.ittimes = \
                        self.ittimes[-self.ETA_SMA_WINDOW:] + \
                        [(time.time() - self.start) / (progress + 1)]
                    self.eta = \
                        sum(self.ittimes) / len(self.ittimes) * \
                        (self.expected_size - progress)
                    self.etadisp = self.format_time(self.eta)
            else:
                self.etadisp = '--:--:--'
        else:
            self.elapsed = time.time() - self.start
            elapsed_disp = self.format_time(self.elapsed)

        time_disp = self.etadisp if self.expected_size else elapsed_disp
        time_label = 'eta' if self.expected_size else 'elapsed'
        expected_disp = '{:<,d}'.format(self.expected_size) if self.expected_size else '--'
        percent_disp = '{:6.2f}%'.format(trunc(progress/self.expected_size*100*100)/100) if self.expected_size else ''

        if not self.hide:
            #if ((progress % self.every) == 0 or  # True every "every" updates
            if ((progress % self.every) == 0 or (progress - self.delta_progress) // self.every >= 1 or  # True every "every" updates
                    (self.expected_size and progress == self.expected_size)):  # And when we're done

                # self.STREAM.write(self.MILL_TEMPLATE % (
                #     self.label, self.mill_char(progress), str(progress), expected, elapsed))
                self.STREAM.write(self.MILL_TEMPLATE.format(self.label, self.mill_char(self.every_progress),
                                                            progress, expected_disp, percent_disp, time_label, time_disp))
                self.STREAM.flush()

                self.delta_progress = progress
                self.every_progress += self.every

    def done(self):
        self.elapsed = time.time() - self.start
        elapsed_disp = self.format_time(self.elapsed)
        time_label = 'elapsed'
        expected_disp = '{:<,d}'.format(self.expected_size) if self.expected_size else '--'
        percent_disp = '{:6}%'.format(trunc(self.last_progress/self.expected_size*100)) if self.expected_size else ''

        if not self.hide:
            self.STREAM.write(self.MILL_TEMPLATE.format(
                self.label, ' ', self.last_progress, expected_disp, percent_disp, time_label, elapsed_disp))
            self.STREAM.write('\n')
            self.STREAM.flush()


class BDownloader(object):
    """The class for executing and managing download jobs.

    The context of the current downloading job is structured as::

        ctx = {
            "total_size": 2000,  # total size of all the to-be-downloaded files, maybe inaccurate due to chunked transfer encoding
            "accurate": True,  # Is `total_size` accurate?
            "files":{
                "file1":{
                    "length": 2000,  # 0 means 'unkown', i.e. file size can't be pre-determined through any one of provided URLs
                    "resumable": True,
                    "download_state": "inprocess",
                    "cancelled_on_exception": False,
                    "futures": [future1, future2],
                    "tsk_num": 2,  # number of the `ranges` and `futures`
                    "orig_path_url": ('file1', 'url1\turl2'),  # (path, url) as a subparameter passed to :meth:`downloads`
                    "urls":{"url1":{"accept_ranges": "bytes", "refcnt": 2}, "url2":{"accept_ranges": "none", "refcnt": 0}},
                    "ranges":{
                        "bytes=0-999": {
                            "start": 0,  # start byte position
                            "end": 999,  # end byte position, None for 'unkown', see above
                            "offset": 0,  # current pointer position relative to 'start'(i.e. 0)
                            "start_time": 0,
                            "rt_dl_speed": 0,  # x seconds interval
                            "download_state": "inprocess",
                           "future": future1,
                           "url": [url1]
                        },
                        "bytes=1000-1999": {
                            "start":1000,
                            "end":1999,
                            "offset": 0,  # current pointer position relative to 'start'(i.e. 1000)
                            "start_time": 0,
                            "rt_dl_speed": 0,  # x seconds interval
                            "future": future2,
                            "url": [url1]
                        }
                    }
                },
                "file2":{
                }
            },
            "futures": {
                future1: {"file": "file1", "range": "bytes=0-999"},
                future2: {"file": "file1", "range": "bytes=1000-1999"}
            }
        }
    """
    # Possible download states of the files and ranges
    INPROCESS = 'inprocess'  # pending or downloading
    FAILED = 'failed'
    SUCCEEDED = 'succeeded'
    CANCELLED = 'cancelled'

    # _COMPLETED = [FAILED, SUCCEEDED]

    _FILE_STATES = [INPROCESS, FAILED, SUCCEEDED]
    _RANGE_STATES = [INPROCESS, FAILED, CANCELLED, SUCCEEDED]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __init__(self, max_workers=None, min_split_size=1024*1024, chunk_size=1024*100, proxy=None, cookies=None,
                 user_agent=None, logger=None, progress='mill', num_pools=20, pool_maxsize=20):
        """Create and initialize a :class:`BDownloader` object.

        Args:
            max_workers (int): The `max_workers` parameter specifies the number of the parallel downloading threads,
                whose default value is determined by ``#num_of_processor * 5`` if set to `None`.
            min_split_size (int): `min_split_size` denotes the size in bytes of file pieces split to be downloaded
                in parallel, which defaults to 1024*1024 bytes (i.e. 1MB).
            chunk_size (int): The `chunk_size` parameter specifies the chunk size in bytes of every http range request,
                which will take a default value of 1024*100 (i.e. 100KB) if not provided.
            proxy (str): The `proxy` supports both HTTP and SOCKS proxies in the form of ``'http://[user:pass@]host:port'``
                and ``'socks5://[user:pass@]host:port'``, respectively.
            cookies (str): If `cookies` needs to be set, it must take the form of ``'cookie_key=cookie_value'``, with
                multiple pairs separated by space character if applicable, e.g. ``'key1=val1 key2=val2'``.
            user_agent (str): When `user_agent` is not given, it will default to ``'bdownload/VERSION'``, with ``VERSION``
                being replaced by the package's version number.
            logger (logging.Logger): The `logger` parameter specifies an event logger. If `logger` is not `None`,
                it must be an object of class :class:`logging.Logger` or of its customized subclass.  Otherwise,
                it will use a default module-level logger returned by ``logging.getLogger(__name__)``.
            progress (str): `progress` determines the style of the progress bar displayed while downloading files.
                Possible values are ``'mill'`` and ``'bar'``, and ``'mill'`` is the default.
            num_pools (int): The `num_pools` parameter has the same meaning as `num_pools` in ``urllib3.PoolManager``
                and will eventually be passed to it. Specifically, `num_pools` specifies the number of connection pools
                to cache.
            pool_maxsize (int): `pool_maxsize` will be passed to the underlying ``requests.adapters.HTTPAdapter``.
                It specifies the maximum number of connections to save that can be reused in the urllib3 connection pool.
        """
        self.requester = requests_retry_session(retries=URLLIB3_RETRIES_ON_EXCEPTION,
                                                backoff_factor=RETRY_BACKOFF_FACTOR,
                                                num_pools=num_pools, pool_maxsize=pool_maxsize)
        if proxy is not None:
            self.requester.proxies = dict(http=proxy, https=proxy)
        if cookies is not None:
            self.requester.cookies = _build_cookiejar_from_kvp(cookies)
        if user_agent is not None:
            self.requester.headers.update({'User-Agent': user_agent})

        self.executor = ThreadPoolExecutor(max_workers)
        self.progress_thread = None
        self.mgmnt_thread = None
        self.all_done_event = threading.Event()  # Event signaling the completion of all the download jobs
        self.all_done = False  # Flag denoting the completion of all the download jobs
        # Flag indicating that **all** the download tasks have been submitted, i.e. no more downloads to be added
        self.all_submitted = False
        self.stop = False   # Flag signaling waiting threads to exit
        self._dl_ctx = {"total_size": 0, "accurate": True, "files": {}, "futures": {}}  # see CTX structure definition

        # list: A downloadable subset of all the `(path, url)`\ s that were passed to :meth:`BDownloader.download` or
        # :meth:`BDownloader.downloads`.
        self.active_downloads_added = []
        # list: The non-downloadable `(path, url)`\ s that were filtered out before downloading actually begins.
        # Together with :attr:`BDownloader.active_downloads_added`, they form the whole of the input downloads.
        self.failed_downloads_on_addition = []
        # list: A subset of :attr:`BDownloader.active_downloads_added`, the downloading of which aborted abnormally.
        self.failed_downloads_in_running = []

        if logger is None:
            logger = logging.getLogger(__name__)
        self._logger = logger

        self.min_split_size = min_split_size
        self.chunk_size = chunk_size

        self.progress = progress
        if self.progress not in ('bar', 'mill'):
            self._logger.error("Error: invalid ProgressBar parameter '{}', default to 'mill'".format(self.progress))
            self.progress = 'mill'

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
        parallel = True if ctx_file['length'] and ctx_file['resumable'] else False
        return parallel

    def _is_download_resumable(self, path_name):
        """Check if the current download of the file can be resumed from the point of last interruption through retrying.

        Args:
            path_name (str): The full path name of the file being downloaded.

        Returns:
            bool: ``True`` if the server accepts range requests for the file, otherwise ``False``.
        """
        return True if self._dl_ctx['files'][path_name]['resumable'] else False

    def _get_remote_file_multipart(self, path_name, req_range):
        """The worker thread body for downloading an assigned piece of a file.

        Args:
            path_name (str): The full path name of the file to be downloaded.
            req_range (str): A chunk of the file `path_name` as a range request of the form ``'bytes=start-end'``.

        Returns:
            None.

        Raises:
            requests.RequestException: Raised when connect timeouts, read timeouts, failed connections or bad status
                codes occurred and the retries is exhausted.
            OSError: Raised when file operations failed.
        """
        ctx_range = self._dl_ctx['files'][path_name]['ranges'][req_range]
        url = ctx_range['url'][0]

        max_retries = REQUESTS_RETRIES_ON_STREAM_EXCEPTION

        try:
            with open(path_name, mode='r+b') as fd:
                for tr in range(max_retries+1):
                    # request start position and end position, maybe resuming from a previous failed request
                    range_start, range_end = ctx_range['start'] + ctx_range['offset'], ctx_range['end']
                    ranges = self.calc_req_ranges(range_end - range_start + 1, self.chunk_size, range_start)

                    fd.seek(range_start)

                    for start, end in ranges:
                        req_range_new = "bytes={}-{}".format(start, end)
                        headers = {"Range": req_range_new}

                        r = self.requester.get(url, headers=headers, allow_redirects=True, stream=True)
                        if r.status_code == requests.codes.partial:
                            try:
                                for chunk in r.iter_content(chunk_size=None):
                                    fd.write(chunk)
                                    ctx_range['offset'] += len(chunk)
                            except requests.RequestException as e:
                                self._logger.error("Error while downloading {}(range:{}-{}/{}-{}): '{}'".format(
                                    os.path.basename(path_name), start, end, ctx_range['start'],
                                    ctx_range['end'], str(e)))

                                break
                        else:
                            msg = "Unexpected status code {}, which should have been {}.".format(r.status_code, requests.codes.partial)
                            self._logger.error(msg)
                            raise requests.RequestException(msg)
                    else:
                        break

                    if tr < max_retries:
                        self._logger.error("Retrying {}/{}...".format(tr+1, max_retries))
                        time.sleep(0.1)
                else:
                    raise
        except OSError as e:
            errno = e.errno if sys.platform != "win32" else e.winerror
            self._logger.error("Error number {}: '{}'".format(errno, e.strerror))

            raise

    def _get_remote_file_singlepart(self, path_name, req_range):
        """The worker thread body for downloading the whole of a file, as opposed to :meth:`_get_remote_file_multipart`.

        Args:
            path_name (str): The full path name of the file to be downloaded.
            req_range (str): The whole chunk of the file `path_name` as a mock range request of the form ``'bytes=0-None'``.

        Returns:
            None.

        Raises:
            requests.RequestException: Raised when connect timeouts, read timeouts, failed connections or bad status
                codes occurred and the retries is exhausted.
            OSError: Raised when file operations failed.
        """
        ctx_range = self._dl_ctx['files'][path_name]['ranges'][req_range]
        url = ctx_range['url'][0]

        max_retries = REQUESTS_RETRIES_ON_STREAM_EXCEPTION
        range_req_satisfiable = True  # The serve may choose to ignore the `Range` header
        try:
            with open(path_name, mode='r+b') as fd:
                for tr in range(max_retries+1):
                    if self._is_download_resumable(path_name) and range_req_satisfiable and ctx_range['offset']:
                        # request start position and end position(which here we don't care about), maybe resuming from a previous failed request
                        range_start = ctx_range['start'] + ctx_range['offset']
                        req_range_new = "bytes={}-{}".format(range_start, '')
                        headers = {"Range": req_range_new}
                        status_code = requests.codes.partial
                    else:
                        range_start = ctx_range['start']
                        headers = {}
                        status_code = requests.codes.ok

                    fd.seek(range_start)

                    r = self.requester.get(url, headers=headers, allow_redirects=True, stream=True)
                    if r.status_code == status_code:  # in (requests.codes.ok, requests.codes.partial)
                        try:
                            for chunk in r.iter_content(chunk_size=None):
                                fd.write(chunk)
                                ctx_range['offset'] += len(chunk)

                                if headers:
                                    range_start = ctx_range['start'] + ctx_range['offset']

                            break
                        except requests.RequestException as e:
                            ctx_file = self._dl_ctx['files'][path_name]
                            if ctx_file['length']:
                                range_end = file_end = ctx_file['length']
                            else:
                                range_end = file_end = ''

                            self._logger.error("Error while downloading {}(range:{}-{}/{}-{}): '{}'".format(
                                os.path.basename(path_name), range_start, range_end, ctx_range['start'], file_end, str(e)))
                            if tr < max_retries:
                                self._logger.error("Retrying {}/{}...".format(tr + 1, max_retries))
                                time.sleep(0.1)
                    else:
                        range_req_satisfiable = False
                        msg = "Unexpected status code {}, which should have been {}. This may be caused by unsupported range request.".format(r.status_code, status_code)
                        self._logger.error(msg)
                        if r.status_code == requests.codes.ok:  # In case the server responds with a '200' status code against a range request
                            if tr < max_retries:
                                self._logger.error("Retrying {}/{}...".format(tr + 1, max_retries))
                                time.sleep(0.1)
                        else:
                            raise requests.RequestException(msg)
                else:
                    raise
        except OSError as e:
            errno = e.errno if sys.platform != "win32" else e.winerror
            self._logger.error("Error number {}: '{}'".format(errno, e.strerror))

            raise

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

    def _build_ctx_internal(self, path_name, url):
        """The helper method that actually does the build of the downloading context of the file.

        Args:
            path_name (str): The full path name of the file to be downloaded.
            url (str): The URL referencing the target file.

        Returns:
            tuple: A 3-tuple ``'(downloadable, (path, url), (orig_path, orig_url))'``, where the ``downloadable``
                indicates whether or not (``True`` or ``False``) there is at least one active URL to download the file,
                ``(path, url)`` denotes the converted full pathname and the URL that consists only of active URLs, and
                ``(orig_path, orig_url)`` denotes the originally input pathname and URL.

        Raises:
            OSError: Raised when file (and path) operations failed.
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
            file_name = None
            file_path = path_name
        else:
            file_name = path_tail
            file_path = path_head

        urls = url.split('\t')  # maybe TAB-separated URLs
        ctx_file = {'length': 0, 'resumable': False, 'download_state': self.INPROCESS, 'cancelled_on_exception': False,
                    'futures': [], 'tsk_num': 0, 'orig_path_url': orig_path_url, 'urls': {}, 'ranges': {}}

        active_urls = []
        downloadable = False  # Must have at least one active URL to download the file
        for _, url in enumerate(urls):
            try:
                r = self.requester.get(url, allow_redirects=True, stream=True)
                if r.status_code == requests.codes.ok:
                    file_len = int(r.headers.get('Content-Length', 0))
                    if file_len:
                        if not ctx_file['length']:
                            ctx_file['length'] = file_len
                        else:
                            if file_len != ctx_file['length']:
                                self._logger.error("File size obtained from '{}' happened to mismatch with that from others, downloading will continue but the downloaded file may be incorrect!".format(
                                    url))

                                r.close()
                                continue

                    ctx_url = ctx_file['urls'][url] = {}
                    ctx_url['accept_ranges'] = "none"
                    ctx_url['refcnt'] = 0

                    accept_ranges = r.headers.get('Accept-Ranges')
                    if "bytes" == accept_ranges:
                        ctx_url['accept_ranges'] = accept_ranges
                        ctx_file['resumable'] = True

                    if not file_name:
                        content_disposition = r.headers.get('Content-Disposition')
                        if content_disposition:
                            file_name = self._get_fname_from_hdr(content_disposition)

                    downloadable = True
                    active_urls.append(url)
                else:
                    self._logger.warning("Unexpected status code {}: trying to determine the file size using '{}'".format(
                        r.status_code, url
                    ))

                r.close()
            except requests.RequestException as e:
                self._logger.error("Error while trying to determine the file size using '{}': '{}'".format(url, str(e)))

        if downloadable:
            if not file_name:
                file_name = self._get_fname_from_url(active_urls[0])

            file_path_name = os.path.abspath(os.path.join(file_path, file_name))
            try:
                if file_path and not os.path.exists(file_path):
                    mkpath(file_path)
                with open(file_path_name, mode='w') as _:
                    pass
            except OSError as e:
                errno = e.errno if sys.platform != "win32" else e.winerror
                self._logger.error("Error number {}: '{}'".format(errno, e.strerror))
                raise

            self._dl_ctx['files'][file_path_name] = ctx_file

            self._dl_ctx['total_size'] += ctx_file['length']
            if not ctx_file['length']:
                self._dl_ctx['accurate'] = False

            # calculate request ranges
            if self._is_parallel_downloadable(file_path_name):
                ranges = self.calc_req_ranges(ctx_file['length'], self.min_split_size, 0)
            else:
                ranges = [(0, None)]

            ctx_file['tsk_num'] = len(ranges)  # How many tasks to complete the download job of the file

            iter_url = self._pick_file_url(file_path_name)
            for start, end in ranges:
                req_range = "bytes={}-{}".format(start, end)
                ctx_range = ctx_file['ranges'][req_range] = {}
                ctx_range.update({
                    'start': start,
                    'end': end,
                    'offset': 0,
                    'start_time': 0,
                    'rt_dl_speed': 0,
                    'download_state': self.INPROCESS,
                    'url': next(iter_url)
                })

            path_url = (file_path_name, '\t'.join(active_urls))

        return downloadable, path_url, orig_path_url

    def _build_ctx(self, path_urls):
        """Build the context for downloading the file(s).

        Args:
            path_urls (list of tuple): Paths and URLs for the file(s) to be downloaded, see :meth:`downloads` for details.

        Returns:
            A 4-tuple of lists ``'(active, active_orig, failed, failed_orig)'``, where the :obj:`list`\ s ``active`` and
                ``active_orig`` contain the active ``(path, url)``'s, converted and original respectively; ``failed``
                and ``failed_orig`` contain the same ``(path, url)``'s that are not downloadable.
        """
        active, active_orig = [], []
        failed, failed_orig = [], []
        for path_name, url in path_urls:
            downloadable, path_url, orig_path_url = self._build_ctx_internal(path_name, url)
            if downloadable:
                active.append(path_url)
                active_orig.append(orig_path_url)
            else:
                failed.append(path_url)
                failed_orig.append(orig_path_url)

        return active, active_orig, failed, failed_orig

    def _future_done_cb(self, future):
        """Update the download states when the worker thread completed.

        This method will be called to update the download states of the interested chunk and the file it belongs to when
        the worker thread completed, ether because of finished without error, raised on exception or cancelled intentionally.

        Args:
            future (concurrent.futures.Future): The ``Future`` instance representing the running of the worker thread
                performing the download of a single chunk or the whole of a file.

        Returns:
            None.
        """
        ctx_file = self._dl_ctx['files'][self._dl_ctx['futures'][future]['file']]
        ctx_range = ctx_file['ranges'][self._dl_ctx['futures'][future]['range']]
        try:
            exception = future.exception()
            if exception is None:
                ctx_range['download_state'] = self.SUCCEEDED
            else:
                ctx_file['download_state'] = self.FAILED
                ctx_range['download_state'] = self.FAILED
        except CancelledError:
            ctx_range['download_state'] = self.CANCELLED

    def _submit_dl_tasks(self, path_urls):
        """Submit the download tasks of the files to the thread pool.

        Args:
            path_urls (list of tuple): The meaning and format of the `path_urls` is similar to the parameter for
                :meth:`downloads`.

        Returns:
            None.
        """
        for path_name, _ in path_urls:
            if self._is_parallel_downloadable(path_name):
                tsk = self._get_remote_file_multipart
            else:
                tsk = self._get_remote_file_singlepart

            ctx_file = self._dl_ctx["files"][path_name]
            for req_range, ctx_range in ctx_file["ranges"].items():
                future = self.executor.submit(tsk, path_name, req_range)
                ctx_file["futures"].append(future)
                ctx_range["future"] = future
                ctx_range["start_time"] = time.time()
                self._dl_ctx["futures"][future] = {
                    "file": path_name,
                    "range": req_range
                }
                future.add_done_callback(self._future_done_cb)

    def _is_all_done(self):
        """Check if all the tasks have completed.

        Returns:
            bool: ``True`` if all the ``Future``s have been done, meaning that all the files have finished downloading,
                whether successfully or not; ``False`` otherwise.
        """
        return all(f.done() for f in self._dl_ctx['futures'])

    def _state_mgmnt(self):
        """Perform the state-related operations of file downloading.

        The only thing this method currently does is to cancel the downloading tasks of a file when it has failed,
        repeatedly on the downloading queue.

        Returns:
            None.
        """
        for ctx_path_name in self._dl_ctx['files'].values():
            if ctx_path_name['download_state'] == self.FAILED and (not ctx_path_name['cancelled_on_exception']):
                fs = ctx_path_name['futures']
                fs_num = len(fs)
                tsk_num = ctx_path_name['tsk_num']
                if fs_num == tsk_num:  # Make sure that all the tasks of the file have been submitted
                    # Cancel the download of the failed file
                    for future in fs:
                        future.cancel()

                    ctx_path_name['cancelled_on_exception'] = True
                    self.failed_downloads_in_running.append(ctx_path_name['orig_path_url'])

    def _mgmnt_task(self):
        """The management thread body.

        This thread manages the downloading process of the whole job queue, currently including state management only.
        When all the tasks have been done, it signals the waiting thread and exits immediately.

        Returns:
            None.
        """
        while not self.all_done:
            self._state_mgmnt()

            if self.all_submitted and self._is_all_done():
                self._state_mgmnt()

                self.all_done_event.set()
                self.all_done = True

            time.sleep(0.1)

    def _calc_completed(self):
        """Calculate the already downloaded bytes of the files.

        Returns:
            int: The size in bytes of the downloaded pieces.
        """
        completed = 0
        for ctx_path_name in self._dl_ctx['files'].values():
            ctx_ranges = ctx_path_name.get('ranges')
            if ctx_ranges:
                for ctx_range in ctx_ranges.values():
                    completed += ctx_range.get('offset', 0)

        return completed

    def _progress_task(self):
        """The thread body for showing the progress of the downloading tasks.

        Returns:
            None.
        """
        total_size = self._dl_ctx['total_size']

        if self._dl_ctx['accurate']:
            if self.progress == 'bar':
                accurate_progress_bar = progress.Bar(expected_size=total_size)
            else:
                accurate_progress_bar = MillProgress(label='Downloaded/Expected:', expected_size=total_size, every=1024)
        else:
            inaccurate_progress_bar = MillProgress(label='Downloaded/Expected(inaccurate):', expected_size=total_size, every=1024)

        progress_bar = accurate_progress_bar if self._dl_ctx['accurate'] else inaccurate_progress_bar
        while not self.stop:
            progress_bar = accurate_progress_bar if self._dl_ctx['accurate'] else inaccurate_progress_bar

            progress_bar.show(self._calc_completed(), count=self._dl_ctx['total_size'])

            time.sleep(0.1)
        else:
            progress_bar.last_progress = self._dl_ctx['total_size'] \
                if self._dl_ctx['accurate'] and not self.failed_downloads_in_running else self._calc_completed()
            progress_bar.expected_size = self._dl_ctx['total_size']
            progress_bar.done()

    def downloads(self, path_urls):
        """Submit multiple downloading jobs at a time to the downloading queue.

        Args:
            path_urls (:obj:`list` of :obj:`tuple`\ s): `path_urls` accepts a list of tuples of the form ``(path, url)``,
                where ``path`` should be a pathname, optionally prefixed with absolute or relative paths, and ``url`` should
                be a URL string, which may consist of multiple TAB-separated URLs pointing to the same file.
                A valid `path_urls`, for example, could be [('/opt/files/bar.tar.bz2', ``'https://foo.cc/bar.tar.bz2'``),
                ('./sanguoshuowen.pdf', ``'https://bar.cc/sanguoshuowen.pdf\\thttps://foo.cc/sanguoshuowen.pdf'``),
                ('/**to**/**be**/created/', ``'https://flash.jiefang.rmy/lc-cl/gaozhuang/chelsia/rockspeaker.tar.gz'``),
                ('/path/to/**existing**-dir', ``'https://ghosthat.bar/foo/puretonecone81.xz\\thttps://tpot.horn/foo/puretonecone81.xz\\thttps://hawkhill.bar/foo/puretonecone81.xz'``)].

        Returns:
            None.
        """
        for chunk_path_urls in self.list_split(path_urls, chunk_size=2):
            active, active_orig, _, failed_orig = self._build_ctx(chunk_path_urls)
            if active:
                if self.progress_thread is None:
                    self.progress_thread = threading.Thread(target=self._progress_task)
                    self.progress_thread.start()

                if self.mgmnt_thread is None:
                    self.mgmnt_thread = threading.Thread(target=self._mgmnt_task)
                    self.mgmnt_thread.start()

                self._submit_dl_tasks(active)
                self.active_downloads_added.extend(active_orig)

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
        """
        return self.downloads([(path_name, url)])

    def wait_for_all(self):
        """Wait for all the downloading jobs to complete.

        Returns:
            tuple of list: A 2-tuple of lists ``'(succeeded, failed)'``. The first list ``succeeded`` contains the
                originally passed ``(path, url)``s that finished successfully, while the second list ``failed`` contains
                the raised and cancelled ones.
        """
        self.all_submitted = True
        if self.active_downloads_added:
            self.all_done_event.wait()

        # return both the succeeded and failed downloads
        succeeded = [path_url for path_url in self.active_downloads_added if path_url not in self.failed_downloads_in_running]
        failed = self.failed_downloads_on_addition + self.failed_downloads_in_running

        return succeeded, failed

    def close(self):
        """Shut down and perform the cleanup.

        Returns:
            None.
        """
        self.executor.shutdown()

        self.stop = True
        if self.progress_thread is not None:
            self.progress_thread.join()

        if self.mgmnt_thread is not None:
            self.mgmnt_thread.join()
