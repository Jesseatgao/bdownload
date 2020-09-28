## bdownload
[![Latest Version](https://img.shields.io/pypi/v/bdownload.svg)](https://pypi.org/project/bdownload/)
[![Build Status](https://travis-ci.com/Jesseatgao/bdownload.svg?branch=master)](https://travis-ci.com/Jesseatgao/bdownload)
[![Supported Versions](https://img.shields.io/pypi/pyversions/bdownload.svg)](https://pypi.org/project/bdownload)

A multi-threaded aria2-like batch file downloading library for Python

### Usage

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