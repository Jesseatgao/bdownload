from __future__ import absolute_import
from __future__ import unicode_literals

from argparse import ArgumentParser
from os.path import join, normpath, abspath

from .download import BDownloader

DEFAULT_MAX_WORKER = 20
DEFAULT_MIN_SPLIT_SIZE = 1024*1024
DEFAULT_CHUNK_SIZE = 1024*10


def arg_parser():
    parser = ArgumentParser()

    parser.add_argument('-o', '--output', nargs='+', required=True, dest='output',
                        help='one or more file names, e.g. "file1.zip file2.tgz", paired with URLs specified by --url')
    parser.add_argument('--url', nargs='+', required=True, dest='url', help='URL(s) for files to be downloaded')
    parser.add_argument('-D', '--dir', default='.', dest='dir', help='path to save the downloaded files')
    parser.add_argument('-p', '--proxy', dest='proxy', default=None,
                        help='proxy in the form of "http://[user:pass@]host:port" or "socks5://[user:pass@]host:port" ')
    parser.add_argument('-n', '--max-workers', dest='max_workers', default=DEFAULT_MAX_WORKER, type=int, help='number of worker threads')
    parser.add_argument('-k', '--min-split-size', dest='min_split_size', default=DEFAULT_MIN_SPLIT_SIZE, type=int, help='file split size')
    parser.add_argument('-s', '--chunk-size', dest='chunk_size', default=DEFAULT_CHUNK_SIZE, type=int, help='every request range size')
    parser.add_argument('-e', '--cookie', dest='cookie', default=None,
                        help='cookies in the form of "cookie_key=cookie_value cookie_key2=cookie_value2"')
    parser.add_argument('--user-agent', dest='user_agent', default=None, help='custom user agent')
    parser.add_argument('-P', '--progress', dest='progress', default='mill', choices=['mill', 'bar'], help='progress indicator')

    return parser


def main():
    args = arg_parser().parse_args()

    files = [abspath(normpath(join(args.dir, f))) for f in args.output]
    file_urls = list(zip(files, args.url))

    with BDownloader(max_workers=args.max_workers, min_split_size=args.min_split_size, chunk_size=args.chunk_size,
                     proxy=args.proxy, cookies=args.cookie, user_agent=args.user_agent, progress=args.progress) as downloader:
        downloader.downloads(file_urls)