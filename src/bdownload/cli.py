# -*- coding: utf-8 -*-
"""This module provides the entry point `main` for the command line utility ``bdownload``.

"""
from __future__ import absolute_import
from __future__ import unicode_literals

import sys
from platform import system
from argparse import ArgumentParser, ArgumentTypeError
from os.path import join, abspath
import re
from codecs import encode, decode
import logging

from .download import BDownloader


DEFAULT_MAX_WORKER = 20         # number of worker threads
DEFAULT_MIN_SPLIT_SIZE = "1M"   # file split size in bytes[1M = 1024*1024]
DEFAULT_CHUNK_SIZE = "100K"     # every request range size in bytes[1K = 1024]
DEFAULT_NUM_POOLS = 20          # number of connection pools
DEFAULT_POOL_SIZE = 20          # max number of connections in the pool


def _win32_utf8_argv():
    """Use ``kernel32.GetCommandLineW`` and ``shell32.CommandLineToArgvW`` to get ``sys.argv`` as a list of UTF-8 strings.

    Versions 2.5 and older of Python don't support Unicode ("mon€y röcks" for example) in ``sys.argv`` on Windows, with
    the underlying Windows API instead replacing multi-byte characters with '?'.

    Returns:
         list of str: Command-line arguments. A list of utf-8 strings for success, None on failure.

    References:
        .. [1] https://code.activestate.com/recipes/572200/
        .. [2] https://stackoverflow.com/questions/846850/read-unicode-characters-from-command-line-arguments-in-python-2-x-on-windows
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
        url (str): URL for the files to be downloaded, which might be TAB-separated URLs pointing to the same file.

            | Examples of `url` include:
            - ``'https://fakewebsite-01.com/downloads/soulbody4ct.pdf\\thttps://fakewebsite-02.com/archives/soulbody4ct.pdf'``
            - ``'https://fakewebsite-01.com/downloads/ipcress.docx	https://fakewebsite-02.com/archives/ipcress.docx'``
            - ``'https://tianchengren:öp€nsasimi@i.louder.ss\\thttps://fangxun.xiaoqing.sunmoon.xue'``

    Returns:
        str: Decoded URL.

    Raises:
        ArgumentTypeError: Raised when `url` contains URL(s) that don't conform to the format "http[s]://[user:pass@]foo.bar[*]".

    References:
        .. [1] https://stackoverflow.com/questions/1885181/how-to-un-escape-a-backslash-escaped-string
        .. [2] https://stackoverflow.com/questions/34145686/handling-argparse-escaped-character-as-option
        .. [3] https://stackoverflow.com/questions/161738/what-is-the-best-regular-expression-to-check-if-a-string-is-a-valid-url
        .. [4] https://github.com/django/django/blob/master/django/core/validators.py
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
        ArgumentTypeError: Raised when passed `bytes_num` is not either a normal integer decimal number string or
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


def _arg_parser():
    parser = ArgumentParser()

    parser.add_argument('-o', '--output', nargs='+', dest='output',
                        help='one or more file names (optionally prefixed with relative (to `-D DIR`) or absolute paths), '
                             'e.g. `-o file1.zip ~/file2.tgz`, paired with URLs specified by `--url` or `-L`')

    parser.add_argument('-L', '--url', nargs='+', required=True, dest='urls', type=_dec_raw_tab_separated_urls,
                        help='URL(s) for the files to be downloaded, '
                             'which might be TAB-separated URLs pointing to the same file, '
                             'e.g. `-L https://yoursite.net/yourfile.7z`, '
                             '`-L "https://yoursite01.net/thefile.7z\\thttps://yoursite02.com/thefile.7z"`, '
                             'or `--url "http://foo.cc/file1.zip" "http://bar.cc/file2.tgz\\thttp://bar2.cc/file2.tgz"`')

    parser.add_argument('-D', '--dir', default='.', dest='dir', help='directory in which to save the downloaded files')

    parser.add_argument('-p', '--proxy', dest='proxy', default=None,
                        help='proxy in the form of "http://[user:pass@]host:port" or "socks5://[user:pass@]host:port" ')

    parser.add_argument('-n', '--max-workers', dest='max_workers', default=DEFAULT_MAX_WORKER, type=int,
                        help='number of worker threads [default: {}]'.format(DEFAULT_MAX_WORKER))

    parser.add_argument('-k', '--min-split-size', dest='min_split_size', default=DEFAULT_MIN_SPLIT_SIZE, type=_normalize_bytes_num,
                        help='file split size in bytes, "1048576, 1024K or 2M" for example [default: {}]'.format(DEFAULT_MIN_SPLIT_SIZE))

    parser.add_argument('-s', '--chunk-size', dest='chunk_size', default=DEFAULT_CHUNK_SIZE, type=_normalize_bytes_num,
                        help='every request range size in bytes, "10240, 10K or 1M" for example [default: {}]'.format(DEFAULT_CHUNK_SIZE))

    parser.add_argument('-e', '--cookie', dest='cookie', default=None,
                        help='cookies in the form of "cookie_key=cookie_value cookie_key2=cookie_value2"')

    parser.add_argument('--user-agent', dest='user_agent', default=None, help='custom user agent')

    parser.add_argument('-P', '--progress', dest='progress', default='mill', choices=['mill', 'bar'],
                        help='progress indicator [default: mill]')

    parser.add_argument('--num-pools', dest='num_pools', default=DEFAULT_NUM_POOLS, type=int,
                        help='number of connection pools [default: {}]'.format(DEFAULT_NUM_POOLS))

    parser.add_argument('--pool-size', dest='pool_size', default=DEFAULT_POOL_SIZE, type=int,
                        help='max number of connections in the pool [default: {}]'.format(DEFAULT_POOL_SIZE))

    return parser


def main():
    """Collect the command-line arguments from ``sys.argv``, parse and do the downloading as specified.
    """
    logging.basicConfig()

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

    files = ['']*len(args.urls) if args.output is None else args.output+['']*(len(args.urls)-len(args.output))
    if len(files) > len(args.urls):
        logging.warning('The specified OUTPUTs and URLs don\'t align, extra OUTPUTs will be ignored: {!r}'.format(args.output[len(args.urls):]))

    path_files = [abspath(join(args.dir, f)) for f in files]
    path_urls = list(zip(path_files, args.urls))

    with BDownloader(max_workers=args.max_workers, min_split_size=args.min_split_size, chunk_size=args.chunk_size,
                     proxy=args.proxy, cookies=args.cookie, user_agent=args.user_agent, progress=args.progress,
                     num_pools=args.num_pools, pool_maxsize=args.pool_size) as downloader:
        downloader.downloads(path_urls)