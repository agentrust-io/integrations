"""Reproduce bounded checks; a known publisher hash failure stays a failure."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from runner import mintid, proofable

ROOT = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fetch', action='store_true', help='download pinned public fixtures')
    args = parser.parse_args()
    if args.fetch:
        subprocess.run([sys.executable, 'fetch_fixtures.py', '--out', 'fixtures'], cwd=ROOT, check=True)
    for path in ('fixtures/download-lock.json', 'fixtures/proofable/manifest.json', 'fixtures/mintid'):
        if not (ROOT / path).exists():
            parser.error('fixtures are required; rerun with --fetch')
    results = ROOT / 'results'
    results.mkdir(exist_ok=True)
    with (results / 'tests.txt').open('w') as output:
        subprocess.run([sys.executable, '-m', 'unittest', '-v'], cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    with (results / 'synthetic-reference.json').open('w') as output:
        subprocess.run([sys.executable, 'reference_adapter.py'], cwd=ROOT, stdout=output, check=True)
    records = [('revocation-trace-testnet-20261006T073712Z', 'mintid-author-testnet.json'),
               ('revocation-trace-local-20261005T094532Z', 'mintid-author-local.json')]
    for name, filename in records:
        report = mintid(ROOT / 'fixtures/mintid', name)
        (results / filename).write_text(json.dumps(report, indent=2) + '\n')
        if report['integrity'] != 'PASS':
            raise RuntimeError('MintID publisher bytes changed: ' + name)
    report = proofable(ROOT / 'fixtures/proofable')
    (results / 'proofable-author.json').write_text(json.dumps(report, indent=2) + '\n')
    mismatches = [c for c in report['checks'] if not c['match']]
    # Both SHA256SUMS and manifest assert the same trace hash. Preserve both failures.
    expected = 'd749cf16fe8dd599f528e21e95863b930004a0b3f0a9882695e3d3b03e8c2183'
    actual = '8df7ed9d49d1d6fb696a05661fd11db194db7c808719a66cadbf0f0a562cc1e2'
    known = len(mismatches) == 2 and all(c['file'] == 'trace.jsonl' and c['expected'] == expected and c['actual'] == actual for c in mismatches)
    if report['integrity'] != 'FAIL' or not known or not report['record_count_consistent']:
        raise RuntimeError('Pinned Proofable evidence changed; review rather than replace expected hashes')
    subprocess.run([sys.executable, 'create_references.py', '--lock', 'fixtures/download-lock.json', '--output', 'results/trace-reference-shapes.json'], cwd=ROOT, check=True)
    print(json.dumps({'package_checks': 'PASS', 'mintid_author_bytes': 'PASS',
                      'proofable_author_bytes': 'FAIL', 'known_failure_preserved': True,
                      'independent_comparison_completed': False}))

if __name__ == '__main__':
    main()
