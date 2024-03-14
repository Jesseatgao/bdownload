# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import sys
import os
import codecs

from argparse import ArgumentParser
import zipfile
import tarfile

from .download import BDownloader, BDownloaderException
from .download import requests_retry_session
from .cli import install_signal_handlers, ignore_termination_signals

_py3plus = (sys.version_info[0] >= 3)  # Is Python version 3 and above?
if not _py3plus:
    # Since the version of 2022.5.18, `certifi` has dropped the support for Python2.7.
    # So we have to obtain the path to the CA bundle by ourselves without really importing `certifi`.
    import imp

    certifi_spec = imp.find_module('certifi')
    certifi_cacert_path = certifi_spec[1]
else:
    from importlib.machinery import PathFinder

    certifi_spec = PathFinder.find_spec('certifi')
    if certifi_spec is not None:
        certifi_cacert_path = os.path.dirname(certifi_spec.origin)
    else:
        raise ModuleNotFoundError("ModuleNotFoundError: No module named 'certifi'")

CACERT_PEM = 'cacert.pem'
certifi_cacert = os.path.join(certifi_cacert_path, CACERT_PEM)

CACERT_VER = 'cacert.ver'  # save the version number of the upgraded `cacert.pem`
certifi_cacert_ver = os.path.join(certifi_cacert_path, CACERT_VER)


def _get_local_cacert_ver():
    if not os.path.exists(certifi_cacert_ver):
        return ''

    with codecs.open(certifi_cacert_ver, 'r', 'utf-8') as fd:
        version = fd.read().strip()

    return version


def _update_local_cacert_ver(new_ver):
    with codecs.open(certifi_cacert_ver, 'w+', 'utf-8') as fd:
        fd.write(new_ver)


def get_latest_tag_github(owner, repo, key, **kwargs):
    """Get the latest tag/version of a GitHub repository.

    Args:
        owner (str): The account owner of the repository.
        repo (str): The name of the repository.
        key (func): A function for extracting comparison key from each tag/version.
        **kwargs: Same arguments as that of :meth:`bdownload.download.RequestsSessionWrapper.__init__()`.

    Returns:
        str: The name of the latest tag.

    Raises:
        exception: Same exception as that raised by :meth:`bdownload.download.RequestsSessionWrapper.get()`.
    """
    rest_api = 'https://api.github.com/repos/%(owner)s/%(repo)s/tags' % {'owner': owner, 'repo': repo}
    headers = {'Accept': 'application/vnd.github.v3+json'}
    requester = requests_retry_session(**kwargs)

    try:
        r = requester.get(rest_api, headers=headers)
        tags = r.json()
        max_tag = max(tags, key=key)
        return max_tag['name']
    except Exception as e:
        print("Error while fetching '%s/%s's latest tag: '%s'" % (owner, repo, str(e)))
        raise


def _key(tag):
    return tag['name'] if not tag['name'].startswith('v') else '1970.01.01'


def _download_certifi(pathname, url, **kwargs):
    ignore_termination_signals()
    downloader = BDownloader(max_workers=1, referrer='*', progress='none', **kwargs)
    install_signal_handlers(downloader)

    try:
        downloader.download(pathname, url)
    except BDownloaderException as e:
        print(str(e))

    downloader.wait_for_all()
    downloader.close()

    result = downloader.result()
    if result:
        raise Exception("Error while downloading the 'certifi' archive...")


def _extract_cacert(from_certifi, member_cacert, to_cacert):
    try:
        if from_certifi.endswith('.zip'):
            with zipfile.ZipFile(from_certifi) as zip_prog:
                with codecs.open(to_cacert, 'w', 'utf-8') as fd:
                    fd.write(zip_prog.read(member_cacert).decode('utf-8'))
        elif from_certifi.endswith('.tar.gz'):
            with tarfile.open(name=from_certifi, mode='r:gz') as gz_prog:
                member_fd = gz_prog.extractfile(member_cacert)
                if member_fd:
                    with codecs.open(to_cacert, 'w', 'utf-8') as fd:
                        fd.write(member_fd.read().decode('utf-8'))
                    member_fd.close()
        else:
            raise Exception("Unsupported compression package format: '%s'" % from_certifi)
    finally:
        os.remove(from_certifi)


def _arg_parser():
    parser = ArgumentParser()

    parser.add_argument('-p', '--proxy', dest='proxy', help='Proxy of the form "http://[user:pass@]host:port" or "socks5://[user:pass@]host:port" ')

    return parser


def update_cacert():
    """Update ``certifi`` to the latest version of certificate authority (CA) bundle on Python2.7.
    """
    if _py3plus:
        print("This utility only supports updating the CA bundle on Python2. For Python3, please run 'pip install -U certifi' to update it instead.")
        sys.exit(-1)

    args = _arg_parser().parse_args()
    kwargs = vars(args)

    try:
        owner = 'certifi'
        repo = 'python-certifi'
        certifi_ext = '.tar.gz'
        latest_ver = get_latest_tag_github(owner=owner, repo=repo, key=_key, **kwargs)
        local_ver = _get_local_cacert_ver()

        if local_ver < latest_ver:
            certifi_root = '%(repo)s-%(ver)s' % {'repo': repo, 'ver': latest_ver}
            certifi_basename = '%(root)s%(ext)s' % {'root': certifi_root, 'ext': certifi_ext}
            certifi = os.path.join(certifi_cacert_path, certifi_basename)
            certifi_url = 'https://github.com/%(owner)s/%(repo)s/archive/refs/tags/%(ver)s%(ext)s' % {'owner': owner, 'repo': repo, 'ver': latest_ver, 'ext': certifi_ext}
            _download_certifi(certifi, certifi_url, **kwargs)

            cacert_path = '/'.join([certifi_root, 'certifi', CACERT_PEM])
            _extract_cacert(certifi, cacert_path, certifi_cacert)

            _update_local_cacert_ver(latest_ver)

            print("The certifi CA bundle has been successfully updated to version '%s'." % latest_ver)
        else:
            print("The certifi CA bundle has already been the latest (%s), so there is nothing left to do." % local_ver)
            sys.exit(-1)
    except Exception as e:
        print("Updating the certifi CA bundle has failed: '%s'" % str(e))
        sys.exit(-1)
