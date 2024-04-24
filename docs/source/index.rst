.. bdownload documentation master file

bdownload
=========
    **A multi-threaded and multi-source aria2-like batch file downloading library for Python 2.7 and 3.6+**

Installation
------------
* via PyPI

    ``$ pip install bdownload``

* from within source directory locally

    ``$ pip install .``

    Note that you should ``git clone`` or download the source tarball (and unpack it of course) from the repository first

.. admonition:: Notes

    **For Python2.7**:  Since the version of 2022.5.18, ``certifi`` has dropped the support for Python2.x. To upgrade to
    the latest CA certificates bundle after installation, simply run:

        ``$ bdownload-upd-cacert-py2``

Usage: as a Python package
--------------------------
Importing
^^^^^^^^^
    ``from bdownload import BDownloader, BDownloaderException``

                    or

    ``import bdownload``

Signatures
^^^^^^^^^^
    For information on the developer interfaces of ``bdownload``, see :ref:`API indices`.

Examples
^^^^^^^^
    * `movie-downloader's third-party programs downloader <https://github.com/Jesseatgao/movie-downloader/blob/32b775c89f273d0b34af6c713e9a9362039b805c/mdl/third_parties/__init__.py#L175>`_
    * :ref:`example_cli`
    * `bdownload's CACERT-updating utility <https://github.com/Jesseatgao/bdownload/blob/master/src/bdownload/utils.py>`_
    * :ref:`test_bdownloader`
    * :ref:`test_multisource_download`

Usage: as a command-line script
-------------------------------
Synopsis
^^^^^^^^
.. code-block:: shell

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

Description
^^^^^^^^^^^

``url``

    URL for the file to be downloaded, which can be either a single URL or TAB-separated composite URL
    pointing to the same file, e.g. `"https://www.afilelink.com/afile.tar.gz"`,
    `"https://chinshou.libccp.mil/luoxuan1981/panjuan-hangyi/tiqianbaozha-key-yasui/qianjunyifa/bengqiyijiao/i-manual/dashboy-basket/zhongzhenkong/xinghuo-xianghui/chunqiao-electronhive-midianfeng/zhenhudan-yasally/afile.tar.gz"`,
    and `"https://www.afilelink.com/afile.tar.gz\thttps://nianpei.bpfatran.com/afile.tar.gz"`

``-L URLS [URLS ...], --url URLS [URLS ...]``

    URL(s) for the files to be downloaded, each of which might contain TAB-separated URLs
    pointing to the same file, e.g. `-L https://yoursite.net/yourfile.7z`,
    `-L "https://yoursite01.net/thefile.7z\thttps://yoursite02.com/thefile.7z"`,
    or `--url "http://foo.cc/file1.zip" "http://bar.cc/file2.tgz\thttp://bar2.cc/file2.tgz"`

``-O OUTPUT, --OUTPUT OUTPUT``

    a save-as file name (optionally with absolute or relative (to ``-D DIR``) path),
    e.g. `-O afile.tar.gz https://www.afilelink.com/afile.tar.gz`

``-o OUTPUT [OUTPUT ...], --output OUTPUT [OUTPUT ...]``

    one or more file names (optionally prefixed with relative (to ``-D DIR``) or absolute paths), e.g.
    `-o file1.zip ~/file2.tgz`, paired with URLs specified by ``--url`` or ``-L``

``-D DIR, --dir DIR``

    directory in which to save the downloaded files [default: directory in which this App is running]

``-p PROXY, --proxy PROXY``

    proxy either in the form of "`http://[user:pass@]host:port`" or "`socks5://[user:pass@]host:port`"

``-n MAX_WORKERS, --max-workers MAX_WORKERS``

    number of worker threads [default: 20]

``-j MAX_PARALLEL_DOWNLOADS, --max-parallel-downloads MAX_PARALLEL_DOWNLOADS``

    number of files downloading concurrently [default: 5]

``-J WORKERS_PER_DOWNLOAD, --workers-per-download WORKERS_PER_DOWNLOAD``

    number of worker threads for every file downloading job [default: 4]

``-k MIN_SPLIT_SIZE, --min-split-size MIN_SPLIT_SIZE``

    file split size in bytes, "1048576, 1024K or 2M" for example [default: 1M]

``-s CHUNK_SIZE, --chunk-size CHUNK_SIZE``

    every request range size in bytes, "10240, 10K or 1M" for example [default: 100K]

``-e COOKIE, --cookie COOKIE``

    cookies either in the form of a string (maybe whitespace- and/or semicolon- separated)
    like "`cookie_key=cookie_value cookie_key2=cookie_value2; cookie_key3=cookie_value3`", or a file,
    e.g. named "cookies.txt", in the Netscape cookie file format. NB the option ``-D DIR`` does not apply to the cookie file

``--user-agent USER_AGENT``

    custom user agent

``--referrer REFERRER``

    HTTP request header "Referer" that applies to all downloads. In particular, use `*` to tell the downloader
    to take the request URL as the referrer per download [default: `*`]

``--check-certificate {True,true,TRUE,False,false,FALSE}``

    whether to verify the server's TLS certificate or not [default: True]

``--ca-certificate CA_CERTIFICATE``

    path to the preferred CA bundle file (.pem) or directory with certificates in PEM format of trusted CAs.
    NB the directory must have been processed using the ``c_rehash`` utility from OpenSSL. Also, the cert files in the directory
    each only contain one CA certificate

``--certificate CERTIFICATE``

    path to a single file in PEM format containing the client certificate and optionally a chain of additional
    certificates. If ``--private-key`` is not provided, then the file must contain the unencrypted private key as well

``--private-key PRIVATE_KEY``

    path to a file containing the unencrypted private key to the client certificate

``-P {mill,bar,none}, --progress {mill,bar,none}``

    progress indicator. To disable this feature, use `none`. [default: mill]

``--num-pools NUM_POOLS``

    number of connection pools [default: 20]

``--pool-size POOL_SIZE``

    max number of connections in the pool [default: 20]

``-l {debug,info,warning,error,critical}, --log-level {debug,info,warning,error,critical}``

    logger level [default: warning]

``-c, --continue``

    resume from the partially downloaded files. This is the default behavior

``--no-continue``

    do not resume from last interruption, i.e. start the download from beginning

``-H HEADER, --header HEADER``

    extra HTTP header, standard or custom, which can be repeated several times, e.g.
    '`-H "User-Agent: John Doe" -H "X-BD-Key: One Thousand And One Nights"`'.The headers take precedence over the ones
    specified by other parameters if conflict happens

``-u USER_PASS, --user-pass USER_PASS``

    default HTTP Authentication for ALL the downloads in "`user:password`" format. Warning: don't use this option
    if not all of the downloads need the authentication to avoid leaking credential, use the ``--netrc-file`` option instead

``--netrc-file NETRC_FILE``

    a .netrc-like file for HTTP authentication, from which the 'default' entry, if present, takes precedence over the
    ``--user-pass`` option

``-h, --help``

    show help message and exit

Examples
^^^^^^^^
    ``$ bdownload https://www.afilelink.com/afile.tar.gz``

    ``$ bdownload -O /abspath/to/afile.tar.gz https://www.afilelink.com/afile.tar.gz``

    ``$ bdownload -O /abspath/to/a/dir/ https://www.afilelink.com/afile.tar.gz``

    ``$ bdownload -O /abspath/to/afile.tar.gz "https://www.afilelink.com/afile.tar.gz\thttps://nianpei.bpfatran.com/afile.tar.gz"``

    ``$ bdownload -D path/to/working_dir/ -O relpath/to/working_dir/alias_afile.tar.gz https://www.afilelink.com/afile.tar.gz``

    ``$ bdownload -D path/to/working/dir https://www.afilelink.com/afile.tar.gz``

    ``$ bdownload -o /abspath/to/file1.zip ~/file2.tgz -L "http://foo.cc/file1.zip" "http://bar.cc/file2.tgz\thttp://bar2.cc/file2.tgz"``

    ``$ bdownload -D path/to/working/dir -L "http://foo.cc/file1.zip" "http://bar.cc/file2.tgz\thttp://bar2.cc/file2.tgz"``

.. _API indices:

API indices
===========
.. toctree::
   :maxdepth: 2

   bdownload


* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
