#!/usr/bin/env python3
"""Restore the pinned browser assets without executing npm lifecycle scripts.

Run from any directory: python scripts/fetch-vendor.py
Sources, versions, archive hashes, asset hashes and license paths are pinned in
web/vendor-lock.json. Internet access is only needed for missing/changed assets.
"""
import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    dest = root / 'web' / 'static' / 'vendor'
    lock = json.loads((root / 'web' / 'vendor-lock.json').read_text(encoding='utf-8'))
    for source in lock['sources']:
        targets = []
        for item in source['files']:
            target = (dest / item['path']).resolve()
            if not target.is_relative_to(dest.resolve()):
                raise ValueError('Asset path escapes vendor directory')
            targets.append((item, target))
        if all(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'] for item, path in targets):
            print(source['package'], source['version'], 'OK')
            continue
        with urllib.request.urlopen(source['url'], timeout=90) as response:
            blob = response.read()
        if hashlib.sha256(blob).hexdigest() != source['sha256']:
            raise ValueError('Archive checksum mismatch: ' + source['package'])
        if source.get('format') == 'file':
            if len(targets) != 1:
                raise ValueError('A standalone source must have exactly one target')
            item, path = targets[0]
            if hashlib.sha256(blob).hexdigest() != item['sha256']:
                raise ValueError('Asset checksum mismatch: ' + item['path'])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
        else:
            restore_archive(blob, targets)
        print(source['package'], source['version'], 'restored')


def restore_archive(blob, targets):
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as archive:
        for item, path in targets:
            member = archive.extractfile(item['member'])
            if member is None:
                raise ValueError('Missing archive member: ' + item['member'])
            content = member.read()
            if hashlib.sha256(content).hexdigest() != item['sha256']:
                raise ValueError('Asset checksum mismatch: ' + item['path'])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)


if __name__ == '__main__':
    main()
