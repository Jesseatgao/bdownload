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
from concurrent.futures import ThreadPoolExecutor  # ,wait
from math import trunc
import re

try:
  from pathlib import Path

  from urllib.parse import unquote, urlparse

  unichr = chr
except ImportError:
  from pathlib2 import Path

  from urllib import unquote
  from urlparse import urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests import Session
from clint.textui import progress


here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, 'VERSION'), mode='r') as fd:
    __version__ = fd.read().strip()


def retry(exceptions, tries=3, backoff_factor=0.1, logger=None):
    """
    Retry calling the decorated function using an exponential backoff.
    Ref: http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
         https://en.wikipedia.org/wiki/Exponential_backoff

    Args:
        exceptions: The exception to check. may be a tuple of
            exceptions to check.
        tries: Number of times to try before giving up.
        backoff_factor:
        logger: Logger to use. None to disable logging.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    def deco_retry(f):

        @wraps(f)
        def f_retry(*args, **kwargs):
            ntries = 0
            while ntries < tries:
                try:
                    return f(*args, **kwargs)
                except exceptions as e:
                    ntries += 1
                    steps = random.randrange(1, 2**ntries)
                    backoff = steps * backoff_factor

                    logger.warning('{!r}, Retrying {}/{} in {:.2f} seconds...'.format(e, ntries, tries, backoff))

                    time.sleep(backoff)

            try:
                return f(*args, **kwargs)
            except exceptions as e:
                logger.warning('{!s}, Having retried {} times, finally failed...'.format(e, ntries))

                raise e

        return f_retry  # true decorator

    return deco_retry


class RequestsSessionWrapper(Session):
    def __init__(self):
        super(RequestsSessionWrapper, self).__init__()

        default_user_agent = 'bdownload/{}'.format(__version__)
        headers = {
            'User-Agent': default_user_agent,
            'Accept-Encoding': 'gzip, identity, deflate, br, *'
        }
        self.headers = headers

    @retry(requests.RequestException)
    def get(self, url, params=None, timeout=(3.2, 6), verify=True, **kwargs):
        return super(RequestsSessionWrapper, self).get(url, params=params, timeout=timeout, verify=verify, **kwargs)


def requests_retry_session(
        retries=2,
        backoff_factor=0.2,
        status_forcelist=(500, 502, 504),
        session=None,
        num_pools=20,
        pool_maxsize=20
):
    """
    Ref: https://www.peterbe.com/plog/best-practice-with-retries-with-requests

    """
    # session = session or requests.Session()
    session = session or RequestsSessionWrapper()

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
    """
    build a CookieJar from key-value pairs of the form "cookie_key=cookie_value cookie_key2=cookie_value2"

    """
    if key_values:
        cookiejar = requests.cookies.RequestsCookieJar()
        kvps = key_values.split()
        for kvp in kvps:
            key, value = kvp.split("=")
            cookiejar.set(key, value)

        return cookiejar


def unquote_unicode(string):
    """https://stackoverflow.com/questions/300445"""
    try:
        if isinstance(string, unicode):
            string = string.encode('utf-8')
        string = unquote(string)  # handle two-digit %hh components first
        parts = string.split(u'%u'.encode('utf-8'))
    except NameError:  # python 3.x has no type called `unicode`
        string = unquote(string)  # handle two-digit %hh components first
        parts = string.split('%u')

    if len(parts) == 1:
        return string
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
    return u''.join(res)


class MillProgress(object):
    """
    Print a mill while progressing.
    Source: grabbed from `clint.textui.progress`, adding support for unknown `expected_size`.
    Source_URL: https://github.com/kennethreitz-archive/clint/blob/master/clint/textui/progress.py
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
    """
    ctx = {
        "total_size": 2000,  # total size of all the to-be-downloaded files, maybe inaccurate due to chunked transfer encoding
        "accurate": True,  # Is `total_size` accurate?
        "files":{
            "file1":{
                "length": 2000,  # 0 means 'unkown', i.e. file size can't be pre-determined through any one of provided URLs
                "resumable": True,
                "urls":{"url1":{"accept_ranges": "bytes", "refcnt": 2}, "url2":{"accept_ranges": "none", "refcnt": 0}},
                "ranges":{
                    "bytes=0-999": {
                        "start": 0,  # start byte position
                        "end": 999,  # end byte position, None for 'unkown', see above
                        "offset": 0,  # current pointer position relative to 'start'(i.e. 0)
                        "start_time": 0,
                        "rt_dl_speed": 0,  # x seconds interval
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
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __init__(self, max_workers=None, min_split_size=1024*1024, chunk_size=1024*100, proxy=None, cookies=None,
                 user_agent=None, logger=None, progress='mill', num_pools=20, pool_maxsize=20):
        self.requester = requests_retry_session(num_pools=num_pools, pool_maxsize=pool_maxsize)
        if proxy is not None:
            self.requester.proxies = dict(http=proxy, https=proxy)
        if cookies is not None:
            self.requester.cookies = _build_cookiejar_from_kvp(cookies)
        if user_agent is not None:
            self.requester.headers.update({'User-Agent': user_agent})

        self.executor = ThreadPoolExecutor(max_workers)
        self.mgmnt_thread = None
        self.stop = False   # Flag signaling waiting threads to exit
        self._dl_ctx = {"total_size": 0, "accurate": True, "files": {}, "futures": {}}  # see CTX structure definition

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
        """Break the list `li` into chunks of size `chunk_size`"""
        for i in range(0, len(li), chunk_size):
            yield li[i:i+chunk_size]

    def _is_parallel_downloadable(self, path_name):
        ctx_file = self._dl_ctx['files'][path_name]
        parallel = True if ctx_file['length'] and ctx_file['resumable'] else False
        return parallel

    def _is_download_resumable(self, path_name):
        return True if self._dl_ctx['files'][path_name]['resumable'] else False

    def _get_remote_file_multipart(self, path_name, req_range):
        ctx_range = self._dl_ctx['files'][path_name]['ranges'][req_range]
        url = ctx_range['url'][0]

        # request start position and end position, maybe resuming from a previous failed request
        range_start, range_end = ctx_range['start'] + ctx_range['offset'], ctx_range['end']
        ranges = self.calc_req_ranges(range_end - range_start + 1, self.chunk_size, range_start)
        with open(path_name, mode='r+b') as fd:
            fd.seek(range_start)

            for start, end in ranges:
                req_range_new = "bytes={}-{}".format(start, end)
                headers = {"Range": req_range_new}
                try:
                    r = self.requester.get(url, headers=headers, allow_redirects=True, stream=True)
                    r.raise_for_status()
                    if r.status_code == requests.codes.partial:
                        for chunk in r.iter_content(chunk_size=None):
                            ctx_range['offset'] += len(chunk)
                            fd.write(chunk)
                    else:
                        msg = "Unexpected status code: {}, which should have been {}.".format(r.status_code, requests.codes.partial)
                        raise requests.RequestException(msg)
                except requests.RequestException as e:
                    self._logger.error("Error while downloading {}(range:{}-{}/{}-{}): '{}'".format(
                        os.path.basename(path_name), range_start, range_end, ctx_range['start'], ctx_range['end'], str(e)))
                    raise

    def _get_remote_file_singlepart(self, path_name, req_range):
        ctx_range = self._dl_ctx['files'][path_name]['ranges'][req_range]
        url = ctx_range['url'][0]

        max_tries = 10
        resume_no_support = False  # In case the server responses with no-support status against a range request
        with open(path_name, mode='r+b') as fd:
            for tr in range(max_tries):
                if self._is_download_resumable(path_name) and not resume_no_support:
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

                try:
                    r = self.requester.get(url, headers=headers, allow_redirects=True, stream=True)
                    r.raise_for_status()
                    if r.status_code == status_code:  # in (requests.codes.ok, requests.codes.partial)
                        for chunk in r.iter_content(chunk_size=None):
                            ctx_range['offset'] += len(chunk)
                            fd.write(chunk)

                            if headers:
                                range_start = ctx_range['start'] + ctx_range['offset']
                                req_range_new = "bytes={}-{}".format(range_start, '')
                                headers['Range'] = req_range_new

                        break
                    else:
                        resume_no_support = True
                        self._logger.error("Unexpected status code: {}, which should have been {}. This may be caused by unsupported range request.".format(r.status_code, status_code))
                        if tr < max_tries - 1:
                            self._logger.error("Retrying {}/{}...".format(tr + 1, max_tries - 1))
                            time.sleep(0.1)
                except requests.RequestException as e:
                    ctx_file = self._dl_ctx['files'][path_name]
                    if ctx_file['length']:
                        range_end = file_end = ctx_file['length']
                    else:
                        range_end = file_end = ''

                    self._logger.error("Error while downloading {}(range:{}-{}/{}-{}): '{}'".format(
                        os.path.basename(path_name), range_start, range_end, ctx_range['start'], file_end, str(e)))
                    if tr < max_tries - 1:
                        self._logger.error("Retrying {}/{}...".format(tr + 1, max_tries - 1))
                        time.sleep(0.1)
            else:
                raise

    def _pick_file_url(self, path_name):
        """Select one URL from multiple sources according to max-connection-per-server etc
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
        """"Get the file name from the Content-Disposition field of the HTTP header
        Ref: https://stackoverflow.com/questions/37060344
        """
        fname = re.findall(r"filename\*=([^;]+)", content_disposition, flags=re.IGNORECASE)
        if not fname:
            fname = re.findall("filename=([^;]+)", content_disposition, flags=re.IGNORECASE)
        if "utf-8''" in fname[0].lower():
            fname = re.sub("utf-8''", '', fname[0], flags=re.IGNORECASE)
            fname = unquote_unicode(fname)
        else:
            fname = fname[0]

        return fname.strip().strip('"')

    @staticmethod
    def _get_fname_from_url(url):
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
        # check whether `path_name` refers to a file (perhaps prefixed with a path) or a directory.
        # If it is a directory, then a file name should be determined through the `url`.
        #
        path_url = (path_name, url)

        if not path_name:
            path_name = '.'
        if url is None:
            url = ''

        path_head, path_tail = os.path.split(path_name)
        if not path_tail or os.path.isdir(path_name):
            file_name = None
            file_path = path_name
        else:
            file_name = path_tail
            file_path = path_head

        urls = url.split('\t')  # maybe TAB-separated URLs
        ctx_file = {'length': 0, 'resumable': False, 'urls': {}, 'ranges': {}}

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

                    content_disposition = r.headers.get('Content-Disposition')
                    if content_disposition and not file_name:
                        file_name = self._get_fname_from_hdr(content_disposition)

                    downloadable = True
                    active_urls.append(url)
                else:
                    self._logger.warning("Status code: {}. Error while trying to determine the file size using '{}'".format(
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
                    Path(file_path).mkdir(parents=True, exist_ok=True)
                with open(file_path_name, mode='w') as _:
                    pass
            except OSError as e:
                self._logger.error("OS error number {}: '{}'".format(e.errno, e.strerror))
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
                    'url': next(iter_url)
                })

            path_url = (file_path_name, '\t'.join(active_urls))

        return downloadable, path_url

    def _build_ctx(self, path_urls):
        built, failed = [], []
        for path_name, url in path_urls:
            downloadable, path_url = self._build_ctx_internal(path_name, url)
            if downloadable:
                built.append(path_url)
            else:
                failed.append(path_url)

        return built, failed

    def _submit_dl_tasks(self, path_urls):
        for path_name, _ in path_urls:
            if self._is_parallel_downloadable(path_name):
                tsk = self._get_remote_file_multipart
            else:
                tsk = self._get_remote_file_singlepart

            for req_range, ctx_range in self._dl_ctx["files"][path_name]["ranges"].items():
                future = self.executor.submit(tsk, path_name, req_range)
                ctx_range["future"] = future
                ctx_range["start_time"] = time.time()
                self._dl_ctx["futures"][future] = {
                    "file": path_name,
                    "range": req_range
                }

    def _is_all_done(self):
        return all(f.done() for f in self._dl_ctx['futures'])

    def _calc_completed(self):
        completed = 0
        for ctx_path_name in self._dl_ctx['files'].values():
            ctx_ranges = ctx_path_name.get('ranges')
            if ctx_ranges:
                for ctx_range in ctx_ranges.values():
                    completed += ctx_range.get('offset', 0)

        return completed

    def _manage_tasks(self):
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
            progress_bar.last_progress = self._dl_ctx['total_size'] if self._dl_ctx['accurate'] else self._calc_completed()
            progress_bar.expected_size = self._dl_ctx['total_size']
            progress_bar.done()

    def downloads(self, path_urls):
        """path_urls: [('path1', 'url1\turl2\turl3'),('path2', 'url4'),]
        """
        for chunk_path_urls in self.list_split(path_urls, chunk_size=2):
            active_path_urls, failed_path_urls = self._build_ctx(chunk_path_urls)
            if active_path_urls:
                if self.mgmnt_thread is None:
                    self.mgmnt_thread = threading.Thread(target=self._manage_tasks)
                    self.mgmnt_thread.start()

                self._submit_dl_tasks(active_path_urls)

            if failed_path_urls:
                self._logger.error('Failed to download: {!r}'.format(failed_path_urls))

        #done, not_done = wait(self._dl_ctx["futures"].keys())

    def download(self, path_name, url):
        return self.downloads([(path_name, url)])

    def wait_for_all(self):
        while True:
            if not self._is_all_done():
                time.sleep(0.1)
            else:
                break

    def close(self):
        self.wait_for_all()
        self.executor.shutdown()

        self.stop = True
        if self.mgmnt_thread is not None:
            self.mgmnt_thread.join()
