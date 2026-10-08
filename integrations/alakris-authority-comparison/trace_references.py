"""TRACE Reference shape checks do not attest unsigned vendor evidence."""
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse
from agentrust_trace import Reference

def behavior_reference(path: Path, pinned_url: str):
    uri = urlparse(pinned_url)
    if uri.scheme != 'https' or not uri.hostname or uri.username is not None or uri.password is not None or any(c.isspace() for c in pinned_url):
        raise ValueError('public evidence reference must be an HTTPS URL without embedded credentials')
    return Reference.model_validate({
        'rel': 'behavior-trace',
        'id': pinned_url,
        'resolver': pinned_url,
        'digest': 'sha256:' + sha256(path.read_bytes()).hexdigest(),
    })
