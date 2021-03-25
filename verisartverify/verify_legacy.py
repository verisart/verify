import base64
import json
from pathlib import Path

from .utils import sha256sum_hex, is_signature_valid, load_json, check_open_timestamp_from_file, unzip


def check_legacy_archive_version_zip(file: Path):
    return check_legacy_archive_version(Path(unzip(file)).joinpath('bag'))


def check_legacy_archive_version(archive_dir: Path):
    dirs = [f for f in archive_dir.joinpath('version').iterdir() if f.is_dir()]

    title = None

    processed_json_files = set()

    version_data = []
    for version_dir in sorted(dirs):
        version_data.append(process_legacy_version(archive_dir, processed_json_files, title, version_dir))

    return version_data


def process_legacy_version(archive_dir, processed_json_files, title, version_dir):
    manifest = version_dir.joinpath('manifest')
    ots = version_dir.joinpath('manifest.ots')
    block, date = check_open_timestamp_from_file(manifest, ots)

    files = check_files(archive_dir, manifest)

    valid_public_keys = set()

    json_files = [file for file in files if file.name.endswith('.json')]
    for json_file in json_files:

        # Each version lists all JSON files known so far so ignore ones handled in a previous version
        if json_file in processed_json_files:
            continue

        data = load_json(json_file)
        payload_base64 = data.get('payload', None)

        if not payload_base64:
            # There are unrelated .json files which we don't care about
            continue

        payload_decoded = base64.b64decode(payload_base64)
        payload = json.loads(payload_decoded.decode('utf-8'))

        if 'crm:P102_has_title' in payload:
            title = payload['crm:P102_has_title']['rdfs:label']

        processed_json_files.add(json_file)

        check_signatures(data, payload_base64, payload_decoded, valid_public_keys)

    return title, valid_public_keys, block, date


def check_signatures(data, payload_base64, payload_decoded, valid_public_keys):
    for signature in data['signatures']:
        public_key = signature['publicKey']
        signature_bytes = base64.b64decode(signature['signature'])

        # The legacy system had two ways of signing: one was to sign the base64 string itself, the other
        # was to sign the decoded base64 contents
        try:
            if not is_signature_valid(public_key, signature_bytes, payload_base64.encode('utf-8')):
                raise Exception('Invalid signature')
        except Exception:
            if not is_signature_valid(public_key, signature_bytes, payload_decoded):
                raise Exception('Invalid signature')

        valid_public_keys.add(public_key)


def check_files(archive_dir, manifest):
    files = []
    for entry in [entry.strip() for entry in manifest.read_text().split('\n') if entry.strip()]:
        parts = entry.split(' ')
        if len(parts):
            hex_hash = parts[0]
            file = archive_dir.joinpath(parts[1])
            if sha256sum_hex(file) != hex_hash:
                raise Exception(f'Hash check failed for file {file}')
            files.append(file)
    return files
