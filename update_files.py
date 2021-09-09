#!/usr/bin/env python3

import subprocess
import os
import datetime
import glob
import functools

import requests


popen = functools.partial(
    subprocess.Popen,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)


def is_outdated(filename: str, fresh_limit: float) -> bool:
    try:
        last_updated = os.stat(filename).st_mtime
        now = datetime.datetime.now().timestamp()
        if (now - last_updated) < (fresh_limit * 86400):
            return False  # less than fresh_limit days since last update

    except FileNotFoundError:  # doesn't exist yet
        pass

    return True


def update_asndb(fresh_limit: float = 7.0, force: bool = False) -> None:
    if not force:
        if not is_outdated('v6.db', fresh_limit):
            return

    print('updating asndb')

    for version in '46':
        dl_proc = popen(['pyasn_util_download.py', f'--latestv{version}'])
        assert dl_proc.stdout and dl_proc.stderr
        if dl_proc.wait():
            print(dl_proc.stdout.read())
            print(dl_proc.stderr.read())
            raise RuntimeError('failed to download ASN database')
        else:
            dl_proc.stdout.close()
            dl_proc.stderr.close()

        db_file = glob.glob('rib.*.bz2')[0]

        convert_proc = popen([
            'pyasn_util_convert.py',
            '--single',
            db_file,
            f'v{version}.db'
        ])
        assert convert_proc.stdout and convert_proc.stderr
        if convert_proc.wait():
            print(convert_proc.stdout.read())
            print(convert_proc.stderr.read())
            raise RuntimeError('failed to convert ASN databases')
        else:
            convert_proc.stdout.close()
            convert_proc.stderr.close()

        os.unlink(db_file)


def update_rir_file(fresh_limit: float = 7.0, force: bool = False) -> None:
    if not force:
        if not is_outdated('delegated-ripencc-extended-latest', fresh_limit):
            return

    print('updating RIR delegates files')
    for rir in ('afrinic', 'apnic', 'arin', 'lacnic', 'ripencc'):
        filename = f'delegated-{rir}-extended-latest'
        data = requests.get(f'https://ftp.ripe.net/pub/stats/{rir}/{filename}').content

        with open(filename, 'wb') as fd:
            fd.write(data)


def update_all() -> None:
    update_asndb()
    update_rir_file()


if __name__ == '__main__':
    update_all()
