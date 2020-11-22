# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest
import tempfile
import os
import hashlib
from shutil import rmtree
from subprocess import Popen, PIPE

# test vectors that use *raw* URL strings mimicking what the `argparse` actually sees
FILES = [
            {
                "file": "gdb-9.2.tar.xz",
                "url": r"https://mirrors.kernel.org/gnu/gdb/gdb-9.2.tar.xz	"
                       r"https://mirror.sergal.org/gnu/gdb/gdb-9.2.tar.xz\t"
                       r"https://mirror.ibcp.fr/pub/gnu/gdb/gdb-9.2.tar.xz",
                "sha1": "356ee474a24bfb2f133894730916557dfea9da2e"
            }
        ]


class TestCommandLineTool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix='bdl-')

        cls.files = FILES
        for f in cls.files:
            f['file'] = os.path.normpath(os.path.join(cls.tmp_dir, f['file']))

    @classmethod
    def tearDownClass(cls):
        rmtree(cls.tmp_dir)

    def test_bdownload(self):
        fi = self.files[-1]
        file_path = fi['file']
        file_url = fi['url']
        file_sha1_exp = fi['sha1']

        cmd = ['bdownload', '-o', file_path, '--url', file_url]
        Popen(cmd, stdout=PIPE).communicate()

        hashf = hashlib.sha1()
        with open(file_path, mode='rb') as f:
            hashf.update(f.read())
        file_sha1 = hashf.hexdigest()

        self.assertEqual(file_sha1_exp, file_sha1)


if __name__ == '__main__':
    unittest.main()
