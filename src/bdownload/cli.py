# -*- coding: utf-8 -*-
"""This module provides the entry point `main` for the command line utility ``bdownload``.

"""
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import sys
from platform import system
from argparse import ArgumentParser, ArgumentTypeError
from os.path import join, abspath, isfile
import re
from codecs import encode, decode
import logging
from functools import partial
import signal
import netrc

from requests.cookies import cookielib

from .download import BDownloader, BDownloaderException, COOKIE_STR_REGEX, HTTP_HEADER_REGEX


DEFAULT_MAX_PARALLEL_DOWNLOADS = 5  # number of files downloading concurrently
DEFAULT_WORKERS_PER_DOWNLOAD = 4    # number of worker threads for every file downloading job
DEFAULT_MAX_WORKER = DEFAULT_MAX_PARALLEL_DOWNLOADS * DEFAULT_WORKERS_PER_DOWNLOAD  # number of worker threads
DEFAULT_MIN_SPLIT_SIZE = "1M"       # file split size in bytes[1M = 1024*1024]
DEFAULT_CHUNK_SIZE = "100K"         # every request range size in bytes[1K = 1024]
DEFAULT_NUM_POOLS = 20              # number of connection pools
DEFAULT_POOL_SIZE = 20              # max number of connections in the pool


def _win32_utf8_argv():
    """Use ``kernel32.GetCommandLineW`` and ``shell32.CommandLineToArgvW`` to get ``sys.argv`` as a list of UTF-8 strings.

    Versions 2.5 and older of Python don't support Unicode ("mon€y röcks" for example) in ``sys.argv`` on Windows, with
    the underlying Windows API instead replacing multi-byte characters with '?'.

    Returns:
         list of str: Command-line arguments. A list of utf-8 strings for success, None on failure.

    References:
        [1] https://code.activestate.com/recipes/572200/

        [2] https://stackoverflow.com/questions/846850/
    """
    try:
        from ctypes import POINTER, byref, cdll, c_int, windll
        from ctypes.wintypes import LPCWSTR, LPWSTR

        GetCommandLineW = cdll.kernel32.GetCommandLineW
        GetCommandLineW.argtypes = []
        GetCommandLineW.restype = LPCWSTR

        CommandLineToArgvW = windll.shell32.CommandLineToArgvW
        CommandLineToArgvW.argtypes = [LPCWSTR, POINTER(c_int)]
        CommandLineToArgvW.restype = POINTER(LPWSTR)

        cmd = GetCommandLineW()
        argc = c_int(0)
        argv = CommandLineToArgvW(cmd, byref(argc))
        if argc.value > 0:
            # Remove Python executable if present
            start = argc.value - len(sys.argv)
            return [argv[i] for i in range(start, argc.value)]
    except Exception:
        pass


def _dec_raw_tab_separated_urls(url):
    """Decode a *raw* URL string that may consist of multiple escaped TAB-separated URLs.

    Args:
        url (str): URL for the file to be downloaded, which might be TAB-separated composite URL pointing to the same file.

    Returns:
        str: Decoded URL.

    Raises:
        ArgumentTypeError: Raised when `url` contains URL(s) that don't conform to the format "http[s]://[user:pass@]foo.bar[*]".

    Examples:
        Examples of the parameter `url` include:
            * ``'https://fakewebsite-01.com/downloads/soulbody4ct.pdf\\thttps://fakewebsite-02.com/archives/soulbody4ct.pdf'``
            * ``'https://fakewebsite-01.com/downloads/ipcress.docx	https://fakewebsite-02.com/archives/ipcress.docx'``
            * ``'https://tianchengren:öp€nsasimi@i.louder.ss\\thttps://fangxun.xiaoqing.sunmoon.xue'``

    References:
        [1] https://stackoverflow.com/questions/1885181/

        [2] https://stackoverflow.com/questions/34145686/

        [3] https://stackoverflow.com/questions/161738/

        [4] https://github.com/django/django/blob/master/django/core/validators.py
    """
    norm_url = decode(encode(url, 'latin-1', 'backslashreplace'), 'unicode_escape')

    # do some basic validation of the `url`
    urls = norm_url.split('\t')
    for suburl in urls:
        try:
            matched = _dec_raw_tab_separated_urls.regex.match(suburl.strip())
        except AttributeError:
            _dec_raw_tab_separated_urls.regex = re.compile(
                r'^https?://'  # scheme
                r'(?:[^\s:@/]+(?::[^\s:@/]*)?@)?'  # user:pass authentication (deprecated)
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
                r'localhost|'  # localhost
                r'(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}|'  # ipv4
                r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ipv6
                r'(?::\d{2,5})?'  # port
                r'(?:/?|[/?]\S+)$',  # resource path
                re.IGNORECASE)
            matched = _dec_raw_tab_separated_urls.regex.match(suburl.strip())

        if not matched:
            msg = '{!r} contains invalid URL(s): not conforming to "http[s]://[user:pass@]foo.bar[*]"'.format(norm_url)
            raise ArgumentTypeError(msg)

    return norm_url


def _normalize_bytes_num(bytes_num):
    """Normalize and convert the integer number string expressed in the unit ``Byte``.

    Args:
        bytes_num (str): The integer number string that may be suffixed with a quantity of 'K' or 'M', where
            'K' indicates multiples of 1024 and 'M' means multiples of *1024\*1024*.

    Returns:
        int: Normalized integer number.

    Raises:
        ArgumentTypeError: Raised when passed `bytes_num` is neither a normal integer decimal number string nor
            a suffixed one.
    """
    try:
        matched = _normalize_bytes_num.regex.match(bytes_num)
    except AttributeError:
        _normalize_bytes_num.regex = re.compile('^[1-9][0-9]*[KM]?$')
        matched = _normalize_bytes_num.regex.match(bytes_num)

    if not matched:
        msg = '{!r} is not a valid integer number, use, for example, 1024, 10K, or 2M instead'.format(bytes_num)
        raise ArgumentTypeError(msg)

    try:
        size = int(bytes_num)
    except ValueError:
        size = int(bytes_num[:-1]) << 20 if bytes_num[-1] == 'M' else int(bytes_num[:-1]) << 10

    return size


def _load_cookies(cookies):
    """Load cookie(s) either from a Netscape cookie file or a string.

    Args:
        cookies (str): Cookies either in the form of a string (maybe whitespace- and/or semicolon- separated)
            like "cookie_key=cookie_value cookie_key2=cookie_value2; cookie_key3=cookie_value3", or a file,
            e.g. named "cookies.txt", in the Netscape cookie file format.

            Note:
                The option `-D DIR` does not apply to the cookie file.

    Returns:
        :obj:`cookielib.MozillaCookieJar` or str: A ``CookieJar`` or a validated cookies string.

    Raises:
        ArgumentTypeError: Raised when exception occurred while loading the `cookies` file or the `cookies` string is
            not in valid format.
    """
    # A cookie file takes precedence over a cookie string
    if isfile(cookies):  # Netscape HTTP Cookie File
        try:
            cj = cookielib.MozillaCookieJar(cookies)
            cj.load(ignore_expires=True, ignore_discard=True)

            return cj
        except EnvironmentError as e:  # `LoadError` is a subclass of which
            raise ArgumentTypeError(str(e))
    else:
        if not COOKIE_STR_REGEX.match(cookies):
            msg = 'Cookie {!r} is not in valid format!'.format(cookies)
            raise ArgumentTypeError(msg)

        return cookies


def _validate_http_header(header):
    """Validate and normalize the HTTP request header."""
    header = header.strip()
    if not HTTP_HEADER_REGEX.match(header):
        msg = 'HTTP header {!r} is not in valid format!'.format(header)
        raise ArgumentTypeError(msg)

    return header


def _validate_netrc_file(file):
    try:
        netrc_auth = {machine: (login, password) for machine, (login, _, password) in netrc.netrc(file).hosts.items()}
        return netrc_auth
    except netrc.NetrcParseError as e:
        raise ArgumentTypeError(str(e))


def _arg_parser():
    parser = ArgumentParser()

    omeg = parser.add_mutually_exclusive_group()
    omeg.add_argument('-O', '--OUTPUT', dest='output', type=lambda f: [f],
                      help='a save-as file name (optionally with absolute or relative (to `-D DIR`) path), '
                           'e.g. `-O afile.tar.gz https://www.afilelink.com/afile.tar.gz`')
    omeg.add_argument('-o', '--output', nargs='+', dest='output',
                      help='one or more file names (optionally prefixed with relative (to `-D DIR`) or absolute paths),'
                           ' e.g. `-o file1.zip ~/file2.tgz`, paired with URLs specified by `--url` or `-L`')

    parser.add_argument('-D', '--dir', default='.', dest='dir',
                        help='directory in which to save the downloaded files [default: directory in which this App is running]')

    lmeg = parser.add_mutually_exclusive_group(required=True)
    lmeg.add_argument('url', nargs='?', type=lambda url: [_dec_raw_tab_separated_urls(url)],
                      help='URL for the file to be downloaded, '
                           'which can be either a single URL or TAB-separated composite URL pointing to the same file, '
                           'e.g. `"https://www.afilelink.com/afile.tar.gz"`, '
                           'and `"https://www.afilelink.com/afile.tar.gz\\thttps://nianpei.bpfatran.com/afile.tar.gz"`')
    lmeg.add_argument('-L', '--url', nargs='+', dest='urls', type=_dec_raw_tab_separated_urls,
                      help='URL(s) for the files to be downloaded, '
                           'each of which might contain TAB-separated URLs pointing to the same file, '
                           'e.g. `-L https://yoursite.net/yourfile.7z`, '
                           '`-L "https://yoursite01.net/thefile.7z\\thttps://yoursite02.com/thefile.7z"`, '
                           'and `--url "http://foo.cc/file1.zip" "http://bar.cc/file2.tgz\\thttp://bar2.cc/file2.tgz"`')

    parser.add_argument('-p', '--proxy', dest='proxy', default=None,
                        help='proxy either in the form of "http://[user:pass@]host:port" or "socks5://[user:pass@]host:port"')

    parser.add_argument('-n', '--max-workers', dest='max_workers', default=DEFAULT_MAX_WORKER, type=int,
                        help='number of worker threads [default: {}]'.format(DEFAULT_MAX_WORKER))

    parser.add_argument('-j', '--max-parallel-downloads', dest='max_parallel_downloads', default=DEFAULT_MAX_PARALLEL_DOWNLOADS, type=int,
                        help='number of files downloading concurrently [default: {}]'.format(DEFAULT_MAX_PARALLEL_DOWNLOADS))

    parser.add_argument('-J', '--workers-per-download', dest='workers_per_download', default=DEFAULT_WORKERS_PER_DOWNLOAD, type=int,
                        help='number of worker threads for every file downloading job [default: {}]'.format(DEFAULT_WORKERS_PER_DOWNLOAD))

    parser.add_argument('-k', '--min-split-size', dest='min_split_size', default=DEFAULT_MIN_SPLIT_SIZE, type=_normalize_bytes_num,
                        help='file split size in bytes, "1048576, 1024K or 2M" for example [default: {}]'.format(DEFAULT_MIN_SPLIT_SIZE))

    parser.add_argument('-s', '--chunk-size', dest='chunk_size', default=DEFAULT_CHUNK_SIZE, type=_normalize_bytes_num,
                        help='every request range size in bytes, "10240, 10K or 1M" for example [default: {}]'.format(DEFAULT_CHUNK_SIZE))

    parser.add_argument('-e', '--cookie', dest='cookie', default=None, type=_load_cookies,
                        help='cookies either in the form of a string (maybe whitespace- and/or semicolon- separated) '
                             'like "cookie_key=cookie_value cookie_key2=cookie_value2; cookie_key3=cookie_value3", or '
                             'a file, e.g. named "cookies.txt", in the Netscape cookie file format. '
                             'NB the option `-D DIR` does not apply to the cookie file')

    parser.add_argument('--user-agent', dest='user_agent', default=None, help='custom user agent')

    parser.add_argument('--referrer', dest='referrer', default='*',
                        help='HTTP request header "Referer" that applies to all downloads. In particular, use "*" to '
                             'tell the downloader to take the request URL as the referrer per download [default: *]')

    parser.add_argument('--check-certificate', dest='check_certificate', default='True',
                        choices=['True', 'true', 'TRUE', 'False', 'false', 'FALSE'],
                        help='whether to verify the server\'s TLS certificate or not [default: True]')

    parser.add_argument('--ca-certificate', dest='ca_certificate', default=None,
                        help='path to the preferred CA bundle file (.pem) or directory with certificates in PEM format '
                             'of trusted CAs. NB the directory must have been processed using the `c_rehash` utility '
                             'from OpenSSL. Also, the cert files in the directory each only contain one CA certificate')

    parser.add_argument('--certificate', dest='certificate', default=None,
                        help='path to a single file in PEM format containing the client certificate and optionally '
                             'a chain of additional certificates. If `--private-key` is not provided, then the file '
                             'must contain the unencrypted private key as well')

    parser.add_argument('--private-key', dest='private_key', default=None,
                        help='path to a file containing the unencrypted private key to the client certificate')

    parser.add_argument('-P', '--progress', dest='progress', default='mill', choices=['mill', 'bar', 'none'],
                        help='progress indicator. To disable this feature, use "none". [default: mill]')

    parser.add_argument('--num-pools', dest='num_pools', default=DEFAULT_NUM_POOLS, type=int,
                        help='number of connection pools [default: {}]'.format(DEFAULT_NUM_POOLS))

    parser.add_argument('--pool-size', dest='pool_size', default=DEFAULT_POOL_SIZE, type=int,
                        help='max number of connections in the pool [default: {}]'.format(DEFAULT_POOL_SIZE))

    parser.add_argument('-l', '--log-level', dest='log_level', default='warning',
                        choices=['debug', 'info', 'warning', 'error', 'critical'], help='logger level [default: warning]')

    cmeg = parser.add_mutually_exclusive_group()
    cmeg.add_argument('-c', '--continue', dest='continuation', action='store_const', const=True,
                      help='resume from the partially downloaded files. This is the default behavior')
    cmeg.add_argument('--no-continue', dest='no_continue', action='store_const', const=True,
                      help='do not resume from last interruption, i.e. start the download from beginning')

    parser.add_argument('-H', '--header', dest='header', action='append', type=_validate_http_header,
                        help='extra HTTP header, standard or custom, which can be repeated several times, '
                             'e.g. \'-H "User-Agent: John Doe" -H "X-BD-Key: One Thousand And One Nights"\'. '
                             'The headers take precedence over the ones specified by other parameters if conflict happens.')
    parser.add_argument('-u', '--user-pass', dest='user_pass',
                        help='default HTTP Authentication for ALL the downloads in \'user:password\' format. '
                             'Warning: don\'t use this option if not all of the downloads need the authentication '
                             'to avoid leaking credential, use the \'--netrc-file\' option instead')
    parser.add_argument('--netrc-file', dest='netrc_file', type=_validate_netrc_file,
                        help='a .netrc-like file for HTTP authentication, from which the \'default\' entry, if present, '
                             'takes precedence over the \'--user-pass\' option')

    return parser


def _interrupt_handler(bdownloader, signum, frame):
    """The handler for the signals ``SIGINT`` and ``SIGQUIT``.

    Args:
        bdownloader (BDownloader): The :obj:`BDownloader` instance acting as the file downloader.
        signum: The signal number being either ``signal.SIGINT`` or ``signal.SIGQUIT``.
        frame: The current stack frame when the signal ``SIGINT`` is received.
    """
    bdownloader.cancel(keyboard_interrupt=True)


def _cmd_quit_handler(bdownloader, signum, frame):
    """The handler for the signals ``SIGTERM``, ``SIGABRT``, ``SIGHUP`` and ``SIGBREAK``.

    Args:
        bdownloader (BDownloader): The :obj:`BDownloader` instance acting as the file downloader.
        signum: The signal number being one of the possible values as ``signal.SIGTERM``, ``signal.SIGABRT``,
            ``signal.SIGHUP``, or ``signal.SIGBREAK``.
        frame: The current stack frame when the signal ``SIGINT`` is received.
    """
    bdownloader.cancel(keyboard_interrupt=False)


def install_signal_handlers(bdownloader):
    """Install handlers for termination signals.

    Args:
        bdownloader (BDownloader): The :obj:`BDownloader` instance acting as the file downloader.
    """
    sig_actions = [('SIGINT', partial(_interrupt_handler, bdownloader)),
                   ('SIGQUIT', partial(_interrupt_handler, bdownloader)),
                   ('SIGTERM', partial(_cmd_quit_handler, bdownloader)),
                   ('SIGABRT', partial(_cmd_quit_handler, bdownloader)),
                   ('SIGHUP', partial(_cmd_quit_handler, bdownloader)),
                   ('SIGBREAK', partial(_cmd_quit_handler, bdownloader))]

    for sig, act in sig_actions:
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), act)


def ignore_termination_signals():
    """Cause the process not to respond to termination signals.
    """
    sigset = ('SIGINT', 'SIGQUIT', 'SIGTERM', 'SIGABRT', 'SIGHUP', 'SIGBREAK')
    actset = (signal.SIG_IGN,) * len(sigset)

    for sig, act in zip(sigset, actset):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), act)


def main():
    """Collect the command-line arguments from ``sys.argv``, parse and do the downloading as specified.
    """
    try:
        unicode

        # for Python 2.x on Windows only
        sys_name = system()
        if sys_name == 'Windows':
            argv = _win32_utf8_argv()
            if argv:
                sys.argv = argv
    except NameError:
        pass

    args = _arg_parser().parse_args()

    log_level = getattr(logging, args.log_level.upper())
    logging.basicConfig(level=log_level)

    continuation = True if args.continuation else False if args.no_continue else True

    check_certificate = True if args.check_certificate.lower() == 'true' else False
    client_certificate = (args.certificate, args.private_key) if args.certificate and args.private_key else args.certificate

    headers = None if not args.header else \
        {name.strip(): value.strip() for name, _, value in [header.partition(':') for header in args.header]}

    default_auth = None
    if args.user_pass:
        user, _, passwd = args.user_pass.partition(":")
        default_auth = (user, passwd)
    if args.netrc_file and args.netrc_file.get('default'):
        default_auth = args.netrc_file['default']

    urls = args.url if args.url else args.urls
    files = ['']*len(urls) if args.output is None else args.output+['']*(len(urls)-len(args.output))
    if len(files) > len(urls):
        print('The specified OUTPUTs and URLs don\'t align, extra OUTPUTs will be ignored: {!r}'.format(args.output[len(urls):]))

    path_files = [abspath(join(args.dir, f)) for f in files]
    path_urls = list(zip(path_files, urls))

    ignore_termination_signals()
    try:
        with BDownloader(max_workers=args.max_workers, max_parallel_downloads=args.max_parallel_downloads,
                         workers_per_download=args.workers_per_download, min_split_size=args.min_split_size,
                         chunk_size=args.chunk_size, proxy=args.proxy, cookies=args.cookie, user_agent=args.user_agent,
                         progress=args.progress, num_pools=args.num_pools, pool_maxsize=args.pool_size, continuation=continuation,
                         referrer=args.referrer, check_certificate=check_certificate, ca_certificate=args.ca_certificate,
                         certificate=client_certificate, auth=default_auth, netrc=args.netrc_file, headers=headers) as downloader:
            install_signal_handlers(downloader)
            downloader.downloads(path_urls)
            succeeded, failed = downloader.wait_for_all()
    except BDownloaderException as e:
        print(str(e))
        succeeded, failed = downloader.results()

    if succeeded:
        print('Succeeded in downloading: {!r}'.format(succeeded))
    if failed:
        print('Failed to download: {!r}'.format(failed))

    exit_code = downloader.result()

    fin_msg = '\nFile(s) downloading was successfully completed!' if not exit_code else '\nFile(s) downloading was aborted with erros!'
    print(fin_msg)

    sys.exit(exit_code)
