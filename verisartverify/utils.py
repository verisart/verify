import base64
import datetime
import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from hashlib import sha256
from pathlib import Path

import ecdsa

OTS_JAR = os.path.dirname(__file__) + '/OtsCli.jar'


def sha256sum_raw(filename):
    h = hashlib.sha256()

    with open(filename, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            h.update(data)
    return h


def sha256sum(filename):
    h = sha256sum_raw(filename)
    return base64.b64encode(h.digest()).decode('utf-8')


def sha256sum_hex(filename):
    return sha256sum_raw(filename).hexdigest()


def load_json(filename):
    with open(filename) as f:
        return json.load(f)


def load_bytes(filename):
    with open(filename, 'rb') as f:
        return f.read()


def unzip(file):
    zip_dir = tempfile.mkdtemp()
    with zipfile.ZipFile(file) as zip_ref:
        zip_ref.extractall(zip_dir)
    return zip_dir


def is_signature_valid(public_key: str, sig: bytes, message: bytes) -> bool:
    try:
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1, hashfunc=sha256)
        return vk.verify(sig, message, sigdecode=ecdsa.util.sigdecode_der)
    except:
        return False


def check_signature(metadata: Path, signature: Path, public_key: str):
    if not is_signature_valid(public_key, load_bytes(signature), load_bytes(metadata)):
        raise Exception(f'Failed check_signature in signature file {signature}')


def parse_iso_datetime(date: str) -> datetime:
    return datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%f%z")


def check_open_timestamp_from_file(manifest: Path, ots_file: Path):
    process_output = subprocess.check_output(['java', '-jar', OTS_JAR, 'verify', '-f', manifest, ots_file],
                                             stderr=subprocess.STDOUT).decode('utf-8')
    pattern = re.compile(r'Success! Bitcoin block (\d+) attests data existed as of (\d\d\d\d-\d\d-\d\d) (\w+)')
    result = pattern.search(process_output)
    if not result:
        raise Exception(f'Failed to find success message in OTS output: {process_output}')
    block = int(result.group(1))
    date = datetime.datetime.strptime(result.group(2) + result.group(3), "%Y-%m-%d%Z").date()
    return block, date


def format_artist_details(artist: dict) -> str:
    attributes = artist['attributes']
    name_object = attributes['name']
    name = name_object['firstName']
    if name_object['lastName']:
        name += " " + name_object['lastName']

    if attributes['yearOfBirth']:
        name += f" ({attributes['yearOfBirth']})"
    return name
