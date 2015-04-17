#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Read directory or file with PKGBUILDs and check for upstream updates.

Requirements:

    yaourt -S python-parched-git python3-aur python-requests python-xdg

validate pkgbuild with namcap
- or use http://jue.li/crux/ck4up/

TODO:

- diff versions (wenn in einer zeile strings diffen, dann rot)
- upstream releases (_watch mit regex)
- print summary at the end of the program like
  x packages scanned, x outdated, x unlisted, x errors
- print stat while scanning
- option: --test-locale / --test-remote. Packete werden in tmp geschoben /
  heruntergeladen und kompiliert zum test.
- --ignore <packages>. Liste von Packetnamen, die nicht geprüft werden sollen
- packages dict is still empty at the end :/
- parse flagged out of date in AUR
- unable to parse array of pkgbuilds
- failed to parse:
  _watch=('http://www.joomla.org/download.html',' ([\d.]*) Full Package,')
  ["'http://www.joomla.org/download.html'", "' ([\\d.]*) Full Package", "'"]
- strict and looseversion:
    # http://stackoverflow.com/questions/1714027/version-number-comparison

_watch='uri','regex' [done]
wenn kein _watch, dann md5sum auf page [done]
wenn nur watch uri, dann md5sum auf watchuri
check return von uri und regex auf versionsnummernsyntax (einzeiler,
zugelassene zeichen), wenn keine versionsnummer, dann return wert wieder
md5summen

"""

import argparse      # command line parsing
import configparser  # to store checksums to .local/share/pkgcheck
import datetime
import hashlib
import os            # filebrowsing
import requests
import re            # regular expressions
import time
import sys

from os.path import join

# non standard-library packages

# to query the AUR via RPC
from AUR.RPC import AUR
# to compare package versions
from distutils.version import LooseVersion, StrictVersion
# to parse PKGBUILD files
from parched import PKGBUILD as Pkgbuild
# xdg basedir where to store program data
from xdg import BaseDirectory as basedir


__version__ = "0.1"


class ParseError(Exception):
    """Error parsing PKGBUILD file."""


def url_regex(url, regex):
    try:
        r = requests.get(url)
    except requests.exceptions.MissingSchema:
        return "Malformed url"

    matchObject = re.search(regex, r.text)

    if matchObject:
        return matchObject.group(1)

    return 0


def url_md5(url):
    try:
        r = requests.get(url)
    except requests.exceptions.MissingSchema:
        raise ValueError("Malformed url: {}".format(url))

    m = hashlib.md5()
    m.update(r.text.encode('utf-8'))
    return m.hexdigest()


def datefmt(seconds, fmt='%Y-%m-%d'):
    """Return unix-timestamp as string formatted date(time).

    Default *fmt* is 'YYYY-mm-dd'

    """
    return datetime.datetime.fromtimestamp(seconds).strftime(fmt)


def check_md5(pkgname, md5sum, config):
    ts = time.time()

    cache_file = join(basedir.xdg_data_home, 'pkgcheck.session')

    if config.read(cache_file):
        if pkgname in config:
            if config.get(pkgname, 'md5sum') == md5sum:
                return "not changed since {}".format(
                    datefmt(config.getfloat(pkgname, 'lastchecked')))
            else:
                return "changed since {}".format(
                    datefmt(config.getfloat(pkgname, 'lastchecked')))
        else:
            config[pkgname] = {'md5sum': md5sum, 'lastchecked': str(ts)}

            with open(cache_file, 'w') as configfile:
                config.write(configfile)

            return "changed since {}".format(datefmt(ts))
    else:
        config[pkgname] = {'md5sum': md5sum, 'lastchecked': str(ts)}

        with open(cache_file, 'w') as configfile:
            config.write(configfile)

        return "changed since {}".format(datefmt(ts))


def parse_watch(filepath):
    with open(filepath) as f:

        for line in f:
            # TODO: match until EOL or Hash for commentary
            p = re.search(r'^\s*_watch\s*=\s*(.*?)$', line)

            if p:
                f.close()
                return p.group(1).strip('(|)').split(",")
                # TODO: Klammern nur am Anfang und Ende stripen


class PkgCheck:
    def __init__(self, filepath, config, aur_session):
        self.filepath = filepath
        self.config = config
        self.aur = aur_session

        try:
            package = Pkgbuild(filepath)
            if isinstance(package.name, list):
                raise NotImplementedError("Split packages not supported yet.")
        except Exception as exc:
            raise ParseError("Error parsing PKGBUILD file: {}".format(filepath))

        try:
            self.aurver = next(aur_session.aur_info(package.name))['Version']
        except StopIteration:
            self.aurver = '-'

        self.pkgname = package.name
        self.pkgver = "{}-{}".format(package.version, int(package.release))

        self.url = package.url or ""
        self.watchurl = ""
        watch_params = parse_watch(filepath)

        if watch_params:
            if len(watch_params) == 2:
                self.upstreamver = url_regex(watch_params[0].strip("'"),
                                             watch_params[1].strip("'"))

            if len(watch_params) == 1:
                self.upstreamver = url_md5(watch_params[0].strip("'"))
        else:
            if self.url:
                self.upstreamver = check_md5(self.pkgname, url_md5(self.url),
                                             self.config)
            else:
                self.upstreamver = "unable to check upstream"

    def check_upstream(self):
        # TODO
        print("check upstream")

    def compare_versions(self):
        if (self.upstreamver > self.pkgver or
                self.upstreamver > self.aurver and self.upstreamver):
            return 1  # red
        else:
            return 0  # green

    def print_row(self, state):
        print("{}{:<20}{:<25}{:<25}{}{}".format(
            '\033[92m' if state else '\033[93m',
            self.pkgname,
            self.pkgver,
            self.aurver,
            self.upstreamver,
            '\033[0m'))

    def test_local(self):
        # TODO
        print("test lokal")

    def test_aur(self):
        # TODO
        print("test aur")

    def fetch_aur(self):
        # TODO
        print("fetch aur")

    def fetch_upstream(self):
        # TODO
        print("fetch upstream")

    def push_aur(self):
        # TODO
        print("push aur")

    def push_git(self):
        # TODO
        print("push git")


def walklevel(some_dir, level):
    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)

    for root, dirs, files in os.walk(some_dir):
        dirs.sort()
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)

        if num_sep + level <= num_sep_this:
            del dirs[:]


def scandir(path, level, print_all=False):
    def nowarn(self, msg):
        pass

    aur_session = AUR()
    aur_session.chwarn(nowarn)
    config = configparser.ConfigParser()
    header = "{:<20}{:<25}{:<25}{}".format("Name", "Local version",
                                           "AUR version", "Upstream version")

    if os.path.isfile(path):
        try:
            package = PkgCheck(path, config, aur_session)
        except ParseError as exc:
            print(str(exc), file=sys.stderr)
            return

        # Print table header
        print(header)
        print("-" * len(header))

        if package.compare_versions() == 0 and print_all:
            package.print_row(1)  # print updated, green packages
        else:
            package.print_row(0)  # print updated, yellow packages
    elif os.path.exists(path):
        # Print table header
        print(header)
        print("-" * len(header))

        package_count = 0

        for (path, dirs, files) in walklevel(path, level):
            if "PKGBUILD" in files:
                package_count += 1
                path = join(path, "PKGBUILD")
                try:
                    package = PkgCheck(path, config, aur_session)
                except ParseError as exc:
                    print(str(exc), file=sys.stderr)
                    continue

                if package.compare_versions() == 0 and print_all:
                    package.print_row(1)  # print updated, green packages
                else:
                    package.print_row(0)  # print updated, yellow packages
    else:
        print("File or directory does not exist.")


def main(args=None):
    """ Function doc

    @param PARAM: DESCRIPTION
    @return RETURN: DESCRIPTION

    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        '-l',
        '--level',
        type=int,
        default=2,
        help="recursion depth for the file crawler (default: %(default)s)")
    parser.add_argument(
        '-a',
        '--all',
        action="store_true",
        help="list all packages, even the up-to-date ones")
    parser.add_argument(
        '-v',
        '--version',
        action="version",
        version=__version__)
    parser.add_argument(
        'DIR',
        default=os.curdir,
        nargs='?',
        help="directory or file with PKGBUILD files(s) (default: %(default)s)")

    args = parser.parse_args(args if args is not None else sys.argv[1:])

    scandir(args.DIR, args.level, args.all)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
