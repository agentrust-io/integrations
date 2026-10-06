"""Fetch immutable public bytes; nothing executes and no publisher hashes are edited."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

PROOFABLE = '3a45f026fd0c06b9d1d411c053597584b6b1c3dc'
MINTID = 'b678e5cd6b5736e1795fd18d497fd8e501272dcd'
RECORDS = ['revocation-trace-testnet-20261006T073712Z', 'revocation-trace-local-20261005T094532Z']

def fetch(out):
    files = {}
    proof_path = 'public/evidence/aaif/authority-at-dispatch/2026-10-06/'
    for name in ['README.md', 'SHA256SUMS', 'manifest.json', 'trace.jsonl', 'authority-effect-results.json', 'authority-effect-results.md']:
        files['proofable/' + name] = f'https://raw.githubusercontent.com/proofable/docs/{PROOFABLE}/{proof_path}{name}'
    for record in RECORDS:
        for suffix in ['.jsonl', '.md', '.manifest.json']:
            files['mintid/' + record + suffix] = f'https://gitlab.com/mintid/mintid/-/raw/{MINTID}/test-harness/trace/records/{record}{suffix}'
    lock = {'proofable_docs_commit': PROOFABLE, 'mintid_public_commit': MINTID, 'files': []}
    for name, url in files.items():
        with urllib.request.urlopen(url, timeout=60) as response:
            content = response.read()
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        lock['files'].append({'path': name, 'url': url, 'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)})
    (out / 'download-lock.json').write_text(json.dumps(lock, indent=2) + '\n')
    print('Fetched', len(files), 'immutable public artifacts')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    fetch(parser.parse_args().out)
