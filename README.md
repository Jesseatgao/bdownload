## bdownload
[![Latest Version](https://img.shields.io/pypi/v/bdownload.svg)](https://pypi.org/project/bdownload/)
[![Build Status](https://travis-ci.com/Jesseatgao/bdownload.svg?branch=master)](https://travis-ci.com/Jesseatgao/bdownload)
[![Supported Versions](https://img.shields.io/pypi/pyversions/bdownload.svg)](https://pypi.org/project/bdownload)

A multi-threaded aria2-like batch file downloading library for Python

### Installation

* via PyPI

    `pip install bdownload`

* from within source directory locally

    `pip install .`
    
    Note that you should `git clone` or download the source tarball (and unpack it of course) from the repository first 

### Usage: as a Python package

#### Importing

    `from bdownload import BDownloader`

            or

    `import bdownload`

#### Signatures

`
class bdownload.BDownloader(max_workers=None, min_split_size=1024*1024, chunk_size=1024*100, proxy=None, cookies=None,
                            user_agent=None, logger=None, progress='mill', num_pools=20, pool_maxsize=20)
`

    Create and initialize a `BDownloader` object for executing download jobs.
  
  * The `max_workers` parameter specifies the number of the parallel downloading threads, whose default value is determined by _#num_of_processor * 5_.
  
  * `min_split_size` denotes the size in bytes of file pieces split to be downloaded in parallel, which defaults to 1024*1024 bytes (i.e. 1MB).
  
  * The `chunk_size` parameter specifies the chunk size in bytes of every http range request, which will take a default value of 1024*100 (i.e. 100KB) if not provided.
  
  * `proxy` supports both HTTP and SOCKS proxies in the form of _http://[user:pass@]host:port_ and _socks5://[user:pass@]host:port_, respectively.
  
  * If `cookies` needs to be set, it must take the form of _cookie_key=cookie_value_, with multiple pairs separated by space character if applicable, e.g. '_key1=val1 key2=val2_'.
  
  * When `user_agent` is not given, it will default to '_bdownload/VERSION_', with _VERSION_ being replaced by the package's version number.
  
  * The `logger` parameter specifies an event logger. If `logger` is not `None`, it must be an object of type `logging.Logger`.  Otherwise, it will use a default module-level logger returned by `logging.getLogger(__name__)`.
  
  * `progress` determines the style of the progress bar displayed while downloading files. Possible values are `'mill'` and `'bar'`, and `'mill'` is the default.
  
  * The `num_pools` parameter has the same meaning as `num_pools` in `urllib3.PoolManager` and will eventually be passed to it. Specifically, `num_pools` specifies the number of connection pools to cache.
  
  * `pool_maxsize` will be passed to the underlying `requests.adapters.HTTPAdapter`. It specifies the maximum number of connections to save that can be reused in the urllib3 connection pool.    

`
BDownloader.downloads(path_urls)
`

    Submit multiple downloading jobs at a time.
  
  * `path_urls` accepts a list of tuples of the form (_path_, _url_), where _path_ should be a pathname, probably prefixed with absolute or relative paths, and _url_ should be a URL string, which may consist of multiple TAB-separated URLs pointing to the same file. A valid `path_urls`, for example, could be [('_/opt/files/bar.tar.bz2_', '_https://foo.cc/bar.tar.bz2_'), ('_./xfile.7z_', '_https://bar.cc/xfile.7z\thttps://foo.cc/xfile.7z_')].

`
BDownloader.download(path, url)
`

    Submit a single downloading job.
  
  * Similar to `BDownloader.downloads()`, in fact it is just a special case of which, with [(_path_, _url_)] composed of the specified parameters as the input.

`
BDownloader.close()
`

    Wait for the jobs done and perform the cleanup. 

#### Examples

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
bdownload [-h] -o OUTPUT [OUTPUT ...] --url URL [URL ...] [-D DIR]
                [-p PROXY] [-n MAX_WORKERS] [-k MIN_SPLIT_SIZE]
                [-s CHUNK_SIZE] [-e COOKIE] [--user-agent USER_AGENT]
                [-P {mill,bar}] [--num-pools NUM_POOLS]
                [--pool-size POOL_SIZE]
```

#### Description

`-o OUTPUT [OUTPUT ...], --output OUTPUT [OUTPUT ...]`

    one or more file names, e.g. `-o file1.zip ~/file2.tgz`, paired with URLs specified by `--url`

`--url URL [URL ...]`

    URL(s) for the files to be downloaded, which might be TAB-separated URLs pointing to the same file, e.g. `--url https://yoursite.net/yourfile.7z`, `--url "https://yoursite01.net/thefile.7z\thttps://yoursite02.com/thefile.7z"`, or `--url "http://foo.cc/file1.zip"  "http://bar.cc/file2.tgz\thttp://bar2.cc/file2.tgz"`

`-D DIR, --dir DIR`

    path to save the downloaded files

`-p PROXY, --proxy PROXY`

    proxy in the form of "http://[user:pass@]host:port" or "socks5://[user:pass@]host:port"

`-n MAX_WORKERS, --max-workers MAX_WORKERS`

    number of worker threads [default: 20]

`-k MIN_SPLIT_SIZE, --min-split-size MIN_SPLIT_SIZE`

    file split size in bytes, "1048576, 1024K or 2M" for example [default: 1M]

`-s CHUNK_SIZE, --chunk-size CHUNK_SIZE`

    every request range size in bytes, "10240, 10K or 1M" for example [default: 100K]

`-e COOKIE, --cookie COOKIE`

    cookies in the form of "cookie_key=cookie_value cookie_key2=cookie_value2"

`--user-agent USER_AGENT`

    custom user agent

`-P {mill,bar}, --progress {mill,bar}`

    progress indicator [default: mill]

`--num-pools NUM_POOLS`

    number of connection pools [default: 20]

`--pool-size POOL_SIZE`

    max number of connections in the pool [default: 20]
