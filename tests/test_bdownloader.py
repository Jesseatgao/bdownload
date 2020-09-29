from __future__ import unicode_literals

import unittest
import tempfile
import os
import hashlib
from shutil import rmtree
from random import sample, seed

from bdownload import BDownloader


FILES = [
            {
                "file": "aria2-x86_64-linux.tar.xz",
                "url": "https://github.com/Jesseatgao/aria2-patched-static-build/releases/download/1.35.0-win-linux/aria2-x86_64-linux.tar.xz",
                "sha1": "d02dfdab7517e78a257f4403e502f1acc2a795e4"
            },
            {
                "file": "mkvtoolnix-x86_64-linux.tar.xz",
                "url": "https://github.com/Jesseatgao/MKVToolNix-static-builds/releases/download/v47.0.0-mingw-w64-win32v1.0/mkvtoolnix-x86_64-linux.tar.xz",
                "sha1": "19b0c7fc20839693cc0929f092f74820783a9750"
            },
            {
                "file": "aria2-x86_64-win.zip",
                "url": "https://github.com/Jesseatgao/aria2-patched-static-build/releases/download/1.35.0-win-linux/aria2-x86_64-win.zip",
                "sha1": "16835c5329450de7a172412b09464d36c549b493"
            },
            {
                "file": "mkvtoolnix-x86_64-win.zip",
                "url": "https://github.com/Jesseatgao/MKVToolNix-static-builds/releases/download/v47.0.0-mingw-w64-win32v1.0/mkvtoolnix-x86_64-win.zip",
                "sha1": "14e9b8eab421fcb225f16191834070217244cf53"
            },
            {
                "file": "aria2-i686-win.zip",
                "url": "https://github.com/Jesseatgao/aria2-patched-static-build/releases/download/1.35.0-win-linux/aria2-i686-win.zip",
                "sha1": "8dc7dc0c25489594d052acfc4415a536b6c2f257"
            },
            {
                "file": "mkvtoolnix-i686-win.zip",
                "url": "https://github.com/Jesseatgao/MKVToolNix-static-builds/releases/download/v47.0.0-mingw-w64-win32v1.0/mkvtoolnix-i686-win.zip",
                "sha1": "80e6d011a053855570471f76e0d1fb8e44af8a78"
            },
            {
                "file": "aria2-i686-linux.tar.xz",
                "url": "https://github.com/Jesseatgao/aria2-patched-static-build/releases/download/1.35.0-win-linux/aria2-i686-linux.tar.xz",
                "sha1": "441af1b5ce83eda9c7a62319b1dfa3fd790882e5"
            },
            {
                "file": "mkvtoolnix-i686-linux.tar.xz",
                "url": "https://github.com/Jesseatgao/MKVToolNix-static-builds/releases/download/v47.0.0-mingw-w64-win32v1.0/mkvtoolnix-i686-linux.tar.xz",
                "sha1": "b917e191106f5b6c0a2186dcaf8599a5481e30b9"
            }
        ]

NUM_SAMPLES = 3


class TestBDownloader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix='bdl-tmp-')

        seed()
        cls.files = [FILES[idx] for idx in sample(range(len(FILES)), NUM_SAMPLES)]
        for f in cls.files:
            f['file'] = os.path.join(cls.tmp_dir, f['file'])

    @classmethod
    def tearDownClass(cls):
        rmtree(cls.tmp_dir)

    def test_bdownloader_download(self):
        fi = self.files[-1]
        file_path = fi['file']
        file_url = fi['url']
        file_sha1_exp = fi['sha1']

        ua = 'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'

        with BDownloader(max_workers=20, user_agent=ua, progress='mill') as downloader:
            downloader.download(file_path, file_url)

        hashf = hashlib.sha1()
        with open(file_path, mode='rb') as f:
            hashf.update(f.read())
        file_sha1 = hashf.hexdigest()

        self.assertEqual(file_sha1_exp, file_sha1)

    def test_bdownloader_downloads(self):
        fs = self.files[:-1]
        file_urls = [(f["file"], f["url"]) for f in fs]

        with BDownloader(max_workers=20, progress='mill') as downloader:
            downloader.downloads(file_urls)

        for f in fs:
            hashf = hashlib.sha1()
            with open(f["file"], mode='rb') as fd:
                hashf.update(fd.read())
            file_sha1 = hashf.hexdigest()

            self.assertEqual(f["sha1"], file_sha1)


if __name__ == '__main__':
    unittest.main()
