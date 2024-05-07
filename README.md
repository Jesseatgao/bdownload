## bdownload
[![Latest Version](https://img.shields.io/pypi/v/bdownload.svg)](https://pypi.org/project/bdownload/)
[![Build Status](https://api.travis-ci.com/Jesseatgao/bdownload.svg?branch=master)](https://api.travis-ci.com/Jesseatgao/bdownload.svg?branch=master)
[![Supported Versions](https://img.shields.io/pypi/pyversions/bdownload.svg)](https://pypi.org/project/bdownload)

A multi-threaded and multi-source aria2-like batch file downloading library for Python 2.7 and 3.6+

> **:bulb:** **Note**\
> See also [https://bdownload.readthedocs.io](https://bdownload.readthedocs.io) for API reference.

### Installation

* via PyPI

    `pip install bdownload`

* from within source directory locally

    `pip install .`
    
    Note that you should `git clone` or download the source tarball (and unpack it of course) from the repository first 

> **:bulb:** **Note**\
> For Python2.7: since the version of 2022.5.18, `certifi` has dropped the support for Python2.x. To upgrade to the latest CA
> certificates bundle, simply run:
> 
> `$ bdownload-upd-cacert-py2`

### Usage: as a Python package

#### Importing

    `from bdownload import BDownloader, BDownloaderException`

            or

    `import bdownload`

#### Signatures

`
class bdownload.BDownloader(max_workers=None, max_parallel_downloads=5, workers_per_download=4, min_split_size=1024*1024,
                            chunk_size=1024*100, proxy=None, cookies=None, user_agent=None, logger=None, progress='mill',
                            num_pools=20, pool_maxsize=20, request_timeout=None, request_retries=None, status_forcelist=None,
                            resumption_retries=None, continuation=True, referrer=None, check_certificate=True, ca_certificate=None,
                            certificate=None, auth=None, netrc=None, headers=None)
`

    Create and initialize a `BDownloader` object for executing download jobs.
  
  * The `max_workers` parameter specifies the number of the parallel downloading threads, whose default value is 
    determined by _#num_of_processor * 5_ if set to `None`.

  * `max_parallel_downloads` limits the number of files downloading concurrently. It has a default value of 5.

  * `workers_per_download` sets the maximum number of worker threads for every file downloading job, which defaults to 4.
  
  * `min_split_size` denotes the size in bytes of file pieces split to be downloaded in parallel, which defaults to 
    1024*1024 bytes (i.e. 1MB).
  
  * The `chunk_size` parameter specifies the chunk size in bytes of every http range request, which will take a default 
    value of 1024*100 (i.e. 100KB) if not provided.
  
  * `proxy` supports both HTTP and SOCKS proxies in the form of _http://[user:pass@]host:port_ and 
    _socks5://[user:pass@]host:port_, respectively.
  
  * If `cookies` needs to be set, it must either take the form of _cookie_key=cookie_value_, with multiple pairs separated
    by whitespace and/or semicolon if applicable, e.g. '_key1=val1 key2=val2;key3=val3_', be packed into a `dict`, or 
    be an instance of `CookieJar`, i.e. `cookielib.CookieJar` for Python27, `http.cookiejar.CookieJar` for Python3.x or 
    `RequestsCookieJar` from `requests`.
    
    Note that the `ValueError` exception will be raised when the `cookies` is of the `str` type and not in the valid format.
  
  * When `user_agent` is not given, it will default to '_bdownload/VERSION_', with _VERSION_ being replaced by the 
    package's version number.
  
  * The `logger` parameter specifies an event logger. If `logger` is not `None`, it must be an object of class 
    `logging.Logger` or of its customized subclass.  Otherwise, it will use a default module-level logger returned by 
    `logging.getLogger(__name__)`.
  
  * `progress` determines the style of the progress bar displayed while downloading files. Possible values are `'mill'`,
    `'bar'` and `'none'`. `'mill'` is the default. To disable this feature, e.g. while scripting or multi-instanced, 
    set it to `'none'`.
  
  * The `num_pools` parameter has the same meaning as `num_pools` in `urllib3.PoolManager` and will eventually be passed
    to it. Specifically, `num_pools` specifies the number of connection pools to cache.
  
  * `pool_maxsize` will be passed to the underlying `requests.adapters.HTTPAdapter`. It specifies the maximum number of 
    connections to save that can be reused in the urllib3 connection pool.

  * The `request_timeout` parameter specifies the timeouts for the internal `requests` session. The timeout value(s) 
    as a float or `(connect, read)` tuple is intended for both the `connect` and the `read` timeouts, respectively.
    If set to `None`, it will take a default value of `(3.05, 6)`.
    
  * `request_retries` specifies the maximum number of retry attempts allowed on exceptions and interested status codes
    (i.e. `status_forcelist`) for the builtin Retry logic of `urllib3`. It will default to `download.URLLIB3_BUILTIN_RETRIES_ON_EXCEPTION`
    if not given.
    
    NB: There are two retry mechanisms that jointly determine the total retries of a request. One is the above-mentioned
    Retry logic that is built into `urllib3`, and the other is the extended high-level retry factor that is meant to 
    complement the builtin retry mechanism. The total retries is bounded by the following formula:
    `request_retries` * (_requests_extended_retries_factor_ + 1), where _requests_extended_retries_factor_ can be modified
    through the module level function `bdownload.set_requests_retries_factor()`, and is initialized to 
    `download.REQUESTS_EXTENDED_RETRIES_FACTOR` by default; Usually you don't want to change it.
    
  * `status_forcelist` specifies a set of HTTP status codes that a retry should be enforced on. The default set of status
    codes shall be `download.URLLIB3_RETRY_STATUS_CODES` if not given.
    
  * The `resumption_retries` parameter specifies the maximum allowable number of retries on error at resuming the interrupted
    download while streaming the request content. The default value of it is `download.REQUESTS_RETRIES_ON_STREAM_EXCEPTION` 
    when not provided.
    
  * The `continuation` parameter specifies whether, if possible, to resume the partially downloaded files before, e.g. 
    when the downloads had been terminated by the user by pressing `Ctrl-C`. When not present, it will default to `True`.
  
  * `referrer` specifies an HTTP request header `Referer` that applies to all downloads. If set to `'*'`, the request URL
    shall be used as the referrer per download.

  * The `check_certificate` parameter specifies whether to verify the server's TLS certificate or not. It defaults to `True`.

  * `ca_certificate` specifies a path to the preferred CA bundle file (.pem) or directory with certificates in PEM format
    of trusted CAs. If set to a path to a directory, the directory must have been processed using the `c_rehash` utility
    supplied with OpenSSL, according to `requests`. NB the cert files in the directory each only contain one CA certificate.

  * `certificate` specifies a client certificate. It has the same meaning as that of `cert` in `requests.request()`.

  * The `auth` parameter sets a (user, pass) tuple or Auth handler to enable Basic/Digest/Custom HTTP Authentication. 
    It will be passed down to the underlying :class:`requests.Session` instance as the default authentication.
    
    > **:warning:** **Warning**\
      The `auth` will be applied to all the downloads for HTTP Authentication. Don't use this parameter, if not all of the
      downloads need the authentication, to avoid leaking credential. Instead, use the `netrc` parameter for fine-grained
      control over HTTP Authentication.

  * `netrc` specifies a dictionary of ``'machine': (login, password)`` (or ``'machine': requests.auth.AuthBase``)
    for HTTP Authentication, similar to the .netrc file format in spirit.

  * `headers` specifies extra HTTP headers, standard or custom, for use in all of the requests made by the session. 
    The headers take precedence over the ones specified by other parameters, e.g. `user_agent`, if conflict happens.

`
BDownloader.downloads(path_urls)
`

    Submit multiple downloading jobs at a time.
  
  * `path_urls` accepts a list of tuples of the form (_path_, _url_), where _path_ should be a pathname, probably prefixed
    with absolute or relative paths, and _url_ should be a URL string, which may consist of multiple TAB-separated URLs 
    pointing to the same file. A valid `path_urls`, for example, could be [('_/opt/files/bar.tar.bz2_', '_https://foo.cc/bar.tar.bz2_'),
    ('_./sanguoshuowen.pdf_', '_https://bar.cc/sanguoshuowen.pdf\thttps://foo.cc/sanguoshuowen.pdf_'), 
    ('_/**to**/**be**/created/_', '_https://flash.jiefang.rmy/lc-cl/gaozhuang/chelsia/rockspeaker.tar.gz_'), ('_/path/to/**existing**-dir_',
    '_https://ghosthat.bar/foo/puretonecone81.xz\thttps://tpot.horn/foo/puretonecone81.xz\thttps://hawkhill.bar/foo/puretonecone81.xz_')].
    
    Note that `BDownloaderException` will be raised if the downloads were interrupted, e.g. by calling
    `BDownloader.cancel()` in a `SIGINT` signal handler, in the process of submitting the download requests.

    > **:warning:** **Warning**\
      The method is not thread-safe, which means it should not be called at the same time in multiple threads
      with one instance.
    > 
    > When multi-instanced (e.g. one instance per thread), the file paths specified in one instance should not overlap 
      those in another to avoid potential race conditions. File loss may occur, for example, if a failed download task 
      in one instance tries to delete a directory that is being accessed by some download tasks in other instances.
      However, this limitation doesn't apply to the file paths specified in a same instance.

`
BDownloader.download(path, url)
`

    Submit a single downloading job.
  
  * Similar to `BDownloader.downloads()`, in fact it is just a special case of which, with [(`path`, `url`)] composed of
    the specified parameters as the input.
    
    Note that `BDownloaderException` will be raised if the download was interrupted, e.g. by calling
    `BDownloader.cancel()` in a `SIGINT` signal handler, in the process of submitting the download request.
    
    > **:warning:** **Warning**\
      The limitation on the method and the `path_name` parameter herein is the same as in `BDownloader.downloads()`.

`
BDownloader.wait_for_all()
`

    Wait for all the downloading jobs to complete. Returns a 2-tuple of lists (_succeeded_, _failed_).
    The first list _succeeded_ contains the originally passed (_path_, _url_)s that completed successfully, while
    the second list _failed_ contains the raised and cancelled ones.

`
BDownloader.results()
`

    Get both the succeeded and failed downloads when all done or interrupted by user. Return a 2-tuple of list
    same as that returned by `BDownloader.wait_for_all()`.

`
BDownloader.result()
`

    Return the final download status. 0 for success, and -1 failure.

`
BDownloader.close()
`

    Shut down and perform the cleanup.

`
BDownloader.cancel(keyboard_interrupt=True)
`

    Cancel all the download jobs.

  * `keyboard_interrupt` specifies whether the user hit the interrupt key (e.g. Ctrl-C).

`
bdownload.set_requests_retries_factor(retries)
`

    Set the retries factor that complements and extends the builtin retry mechanism of `urllib3`.

  * The `retries` parameter specifies the maximum number of retries when a decorated method of `requests` raised an 
    exception or returned any bad status code. It should take a value of at least `1`, or else nothing changes.

#### Examples

* [`movie-downloader`'s third-party programs downloader](https://github.com/Jesseatgao/movie-downloader/blob/32b775c89f273d0b34af6c713e9a9362039b805c/mdl/third_parties/__init__.py#L175)

* [`bdownload`'s command-line utility](https://github.com/Jesseatgao/bdownload/blob/master/src/bdownload/cli.py)

* [`bdownload`'s CACERT-updating utility](https://github.com/Jesseatgao/bdownload/blob/master/src/bdownload/utils.py)

* Single file downloading

```python

import unittest
import tempfile
import os
import hashlib

from bdownload import BDownloader


class TestBDownloader(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_bdownloader_download(self):
        file_path = os.path.join(self.tmp_dir.name, "aria2-x86_64-win.zip")
        file_url = "https://github.com/Jesseatgao/aria2-patched-static-build/releases/download/1.35.0-win-linux/aria2-x86_64-win.zip"
        file_sha1_exp = "16835c5329450de7a172412b09464d36c549b493"

        with BDownloader(max_workers=20, progress='mill') as downloader:
            downloader.download(file_path, file_url)
            downloader.wait_for_all()

        hashf = hashlib.sha1()
        with open(file_path, mode='rb') as f:
            hashf.update(f.read())
        file_sha1 = hashf.hexdigest()

        self.assertEqual(file_sha1_exp, file_sha1)


if __name__ == '__main__':
    unittest.main()

```

* Batch file downloading

```python

import unittest
import tempfile
import os
import hashlib

from bdownload import BDownloader


class TestBDownloader(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_bdownloader_downloads(self):
        files = [
            {
                "file": os.path.join(self.tmp_dir.name, "aria2-x86_64-linux.tar.xz"),
                "url": "https://github.com/Jesseatgao/aria2-patched-static-build/releases/download/1.35.0-win-linux/aria2-x86_64-linux.tar.xz",
                "sha1": "d02dfdab7517e78a257f4403e502f1acc2a795e4"
            },
            {
                "file": os.path.join(self.tmp_dir.name, "mkvtoolnix-x86_64-linux.tar.xz"),
                "url": "https://github.com/Jesseatgao/MKVToolNix-static-builds/releases/download/v47.0.0-mingw-w64-win32v1.0/mkvtoolnix-x86_64-linux.tar.xz",
                "sha1": "19b0c7fc20839693cc0929f092f74820783a9750"
            }
        ]

        file_urls = [(f["file"], f["url"]) for f in files]

        with BDownloader(max_workers=20, progress='mill') as downloader:
            downloader.downloads(file_urls)
            downloader.wait_for_all()

        for f in files:
            hashf = hashlib.sha1()
            with open(f["file"], mode='rb') as fd:
                hashf.update(fd.read())
            file_sha1 = hashf.hexdigest()

            self.assertEqual(f["sha1"], file_sha1)


if __name__ == '__main__':
    unittest.main()

```
### Usage: as a command-line script

#### Synopsis

```
bdownload      url | -L URLS [URLS ...]
               [-O OUTPUT | -o OUTPUT [OUTPUT ...]] [-D DIR]
               [-p PROXY] [-n MAX_WORKERS] [-j MAX_PARALLEL_DOWNLOADS]
               [-J WORKERS_PER_DOWNLOAD] [-k MIN_SPLIT_SIZE] [-s CHUNK_SIZE]
               [-e COOKIE] [--user-agent USER_AGENT] [--referrer REFERRER]
               [--check-certificate {True,true,TRUE,False,false,FALSE}]
               [--ca-certificate CA_CERTIFICATE]
               [--certificate CERTIFICATE] [--private-key PRIVATE_KEY]
               [-P {mill,bar,none}] [--num-pools NUM_POOLS]
               [--pool-size POOL_SIZE] [-l {debug,info,warning,error,critical}]
               [-c | --no-continue] [-H HEADER] [-u USER_PASS] [--netrc-file NETRC_FILE]
               [-h]
```

#### Description

`url`

    URL for the file to be downloaded, which can be either a single URL or TAB-separated composite URL 
    pointing to the same file, e.g. `"https://www.afilelink.com/afile.tar.gz"`, 
    `"https://chinshou.libccp.mil/luoxuan1981/panjuan-hangyi/tiqianbaozha-key-yasui/qianjunyifa/bengqiyijiao/i-manual/dashboy-basket/zhongzhenkong/xinghuo-xianghui/chunqiao-electronhive-midianfeng/zhenhudan-yasally/afile.tar.gz"`,
    and `"https://www.afilelink.com/afile.tar.gz\thttps://nianpei.bpfatran.com/afile.tar.gz"`

`-L URLS [URLS ...], --url URLS [URLS ...]`

    URL(s) for the files to be downloaded, each of which might contain TAB-separated URLs 
    pointing to the same file, e.g. `-L https://yoursite.net/yourfile.7z`, 
    `-L "https://yoursite01.net/thefile.7z\thttps://yoursite02.com/thefile.7z"`, 
    or `--url "http://foo.cc/file1.zip" "http://bar.cc/file2.tgz\thttp://bar2.cc/file2.tgz"`

`-O OUTPUT, --OUTPUT OUTPUT`

    a save-as file name (optionally with absolute or relative (to `-D DIR`) path), 
    e.g. `-O afile.tar.gz https://www.afilelink.com/afile.tar.gz`

`-o OUTPUT [OUTPUT ...], --output OUTPUT [OUTPUT ...]`

    one or more file names (optionally prefixed with relative (to `-D DIR`) or absolute paths), e.g. 
    `-o file1.zip ~/file2.tgz`, paired with URLs specified by `--url` or `-L`

`-D DIR, --dir DIR`

    directory in which to save the downloaded files [default: directory in which this App is running]

`-p PROXY, --proxy PROXY`

    proxy either in the form of "`http://[user:pass@]host:port`" or "`socks5://[user:pass@]host:port`"

`-n MAX_WORKERS, --max-workers MAX_WORKERS`

    number of worker threads [default: 20]

`-j MAX_PARALLEL_DOWNLOADS, --max-parallel-downloads MAX_PARALLEL_DOWNLOADS`

    number of files downloading concurrently [default: 5]

`-J WORKERS_PER_DOWNLOAD, --workers-per-download WORKERS_PER_DOWNLOAD`

    number of worker threads for every file downloading job [default: 4]

`-k MIN_SPLIT_SIZE, --min-split-size MIN_SPLIT_SIZE`

    file split size in bytes, "1048576, 1024K or 2M" for example [default: 1M]

`-s CHUNK_SIZE, --chunk-size CHUNK_SIZE`

    every request range size in bytes, "10240, 10K or 1M" for example [default: 100K]

`-e COOKIE, --cookie COOKIE`

    cookies either in the form of a string (maybe whitespace- and/or semicolon- separated) 
    like "`cookie_key=cookie_value cookie_key2=cookie_value2; cookie_key3=cookie_value3`", or a file, 
    e.g. named "cookies.txt", in the Netscape cookie file format. NB the option `-D DIR` does not apply to the cookie file

`--user-agent USER_AGENT`

    custom user agent

`--referrer REFERRER`

    HTTP request header "Referer" that applies to all downloads. In particular, use `*` to tell the downloader
    to take the request URL as the referrer per download [default: *]

`--check-certificate {True,true,TRUE,False,false,FALSE}`

    whether to verify the server's TLS certificate or not [default: True]

`--ca-certificate CA_CERTIFICATE`

    path to the preferred CA bundle file (.pem) or directory with certificates in PEM format of trusted CAs.
    NB the directory must have been processed using the `c_rehash` utility from OpenSSL. Also, the cert files in the directory
    each only contain one CA certificate

`--certificate CERTIFICATE`

    path to a single file in PEM format containing the client certificate and optionally a chain of additional
    certificates. If `--private-key` is not provided, then the file must contain the unencrypted private key as well

`--private-key PRIVATE_KEY`

    path to a file containing the unencrypted private key to the client certificate

`-P {mill,bar,none}, --progress {mill,bar,none}`

    progress indicator. To disable this feature, use `none`. [default: mill]

`--num-pools NUM_POOLS`

    number of connection pools [default: 20]

`--pool-size POOL_SIZE`

    max number of connections in the pool [default: 20]

`-l {debug,info,warning,error,critical}, --log-level {debug,info,warning,error,critical}`

    logger level [default: warning]

`-c, --continue`

    resume from the partially downloaded files. This is the default behavior

`--no-continue`

    do not resume from last interruption, i.e. start the download from beginning

`-H HEADER, --header HEADER`

    extra HTTP header, standard or custom, which can be repeated several times, e.g. 
    '`-H "User-Agent: John Doe" -H "X-BD-Key: One Thousand And One Nights"`'. The headers take precedence over the ones 
    specified by other parameters if conflict happens

`-u USER_PASS, --user-pass USER_PASS`

    default HTTP Authentication for ALL the downloads in "`user:password`" format. **Warning**: don't use this option
    if not all of the downloads need the authentication to avoid leaking credential, use the `--netrc-file` option instead

`--netrc-file NETRC_FILE`

    a .netrc-like file for HTTP authentication, from which the 'default' entry, if present, takes precedence
    over the `--user-pass` option

`-h, --help`

    show help message and exit

#### Examples

    bdownload https://www.afilelink.com/afile.tar.gz
    bdownload -O /abspath/to/afile.tar.gz https://www.afilelink.com/afile.tar.gz
    bdownload -O /abspath/to/a/dir/ https://www.afilelink.com/afile.tar.gz
    bdownload -O /abspath/to/afile.tar.gz "https://www.afilelink.com/afile.tar.gz\thttps://nianpei.bpfatran.com/afile.tar.gz"
    bdownload -D path/to/working_dir/ -O relpath/to/working_dir/alias_afile.tar.gz https://www.afilelink.com/afile.tar.gz
    bdownload -D path/to/working/dir https://www.afilelink.com/afile.tar.gz
    bdownload -o /abspath/to/file1.zip ~/file2.tgz -L "http://foo.cc/file1.zip" "http://bar.cc/file2.tgz\thttp://bar2.cc/file2.tgz"
    bdownload -D path/to/working/dir -L "http://foo.cc/file1.zip" "http://bar.cc/file2.tgz\thttp://bar2.cc/file2.tgz"
