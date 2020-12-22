# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest
import tempfile
import os
import hashlib
from shutil import rmtree

from bdownload import BDownloader

# Mixed use of two forms of TAB to separate URLs: 'invisible' Tab character "	" or escape sequence "\t"
FILES = [
            {
                "file": "gimp-2.8.22-1.el7.x86_64.rpm",
                "url": "https://mirror.umd.edu/centos/7/os/x86_64/Packages/gimp-2.8.22-1.el7.x86_64.rpm	"
                       "https://mirrors.mit.edu/centos/7/os/x86_64/Packages/gimp-2.8.22-1.el7.x86_64.rpm\t"
                       "https://mirror.arizona.edu/centos/7/os/x86_64/Packages/gimp-2.8.22-1.el7.x86_64.rpm",
                "sha1": "520282f3de34875addb8ad05b7d57f98df6cb64f"
            },
            {
                "file": "valgrind-3.15.0-11.el7.x86_64.rpm",
                "url": "https://mirrors.163.com/centos/7/os/x86_64/Packages/valgrind-3.15.0-11.el7.x86_64.rpm	"
                       "https://mirrors.tuna.tsinghua.edu.cn/centos/7/os/x86_64/Packages/valgrind-3.15.0-11.el7.x86_64.rpm\t"
                       "https://mirrors.aliyun.com/centos/7/os/x86_64/Packages/valgrind-3.15.0-11.el7.x86_64.rpm",
                "sha1": "84866f6c637042297eda09cdd4fed35118c4f507"
            },
            {
                "file": "eclipse_3.8.1.orig.tar.xz",
                "url": "http://ftp.us.debian.org/debian/pool/main/e/eclipse/eclipse_3.8.1.orig.tar.xz	"
                       "http://debian-archive.trafficmanager.net/debian/pool/main/e/eclipse/eclipse_3.8.1.orig.tar.xz\t"
                       "http://ftp.uk.debian.org/debian/pool/main/e/eclipse/eclipse_3.8.1.orig.tar.xz",
                "sha1": "9b8bb069eea91ac7f1b7a3295803056e50e31fa1"
            }
        ]


class TestMultiSourceDownload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix='bdl-')

        cls.files = FILES
        for f in cls.files:
            f['file'] = os.path.normpath(os.path.join(cls.tmp_dir, 'röckshark/高昌/中/南海观音/c-hyphen-key/后海/zhangminguo', f['file']))

    @classmethod
    def tearDownClass(cls):
        rmtree(cls.tmp_dir)

    def test_bdownloader_download(self):
        fi = self.files[-1]
        file_path = fi['file']
        file_url = fi['url']
        file_sha1_exp = fi['sha1']

        with BDownloader(max_workers=20, progress='bar') as downloader:
            downloader.download(file_path, file_url)
            downloader.wait_for_all()

        hashf = hashlib.sha1()
        with open(file_path, mode='rb') as f:
            hashf.update(f.read())
        file_sha1 = hashf.hexdigest()

        self.assertEqual(file_sha1_exp, file_sha1)

    def test_bdownloader_downloads(self):
        fs = self.files[:-1]
        file_urls = [(f["file"], f["url"]) for f in fs]

        with BDownloader(max_workers=20, progress='bar') as downloader:
            downloader.downloads(file_urls)
            downloader.wait_for_all()

        for f in fs:
            hashf = hashlib.sha1()
            with open(f["file"], mode='rb') as fd:
                hashf.update(fd.read())
            file_sha1 = hashf.hexdigest()

            self.assertEqual(f["sha1"], file_sha1)


if __name__ == '__main__':
    unittest.main()
