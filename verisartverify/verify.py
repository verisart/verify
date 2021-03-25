#!/usr/bin/env python3

from pathlib import Path

import requests

from .utils import unzip, load_json, sha256sum, parse_iso_datetime, \
    check_open_timestamp_from_file, check_signature, format_artist_details
from .verify_legacy import check_legacy_archive_version_zip

VERISART_PUBLIC_KEY = "0351734e3561763050a412e788d0a4644150bb434cf586c3780fbf11758057a965"
API_URL = 'https://api.verisart.com/v3'


class VerifyException(Exception):
    pass


def verify_file(file) -> list[str]:
    """
    Verify a Verisart certificate from a file like object

    :param file: file-like object
    :return: The number of warnings
    :raises: VerifyException if verify failed
    """
    return _verify_unzipped_dir(unzip(file))


def verify_path(file: str) -> list[str]:
    """
    Verify a Verisart certificate from a file path (either a zip file or a directory
    of the unzipped contents)

    :param file: file path
    :return: The number of warnings
    :raises: VerifyException if verify failed
    """
    if Path(file).is_file():
        zip_dir = unzip(file)
    else:
        zip_dir = file
    return _verify_unzipped_dir(zip_dir)


def _verify_unzipped_dir(zip_dir: str) -> list[str]:
    zip_dir_path = Path(zip_dir)
    all_files = {i for i in zip_dir_path.glob('**/*')}
    versions_dir = zip_dir_path.joinpath('versions')
    files_dir = zip_dir_path.joinpath('files')
    old_files_dir = zip_dir_path.joinpath('oldFiles')

    versions = [Version(version_dir, files_dir, old_files_dir) for version_dir in
                sorted([v for v in versions_dir.iterdir() if v.is_dir()])]

    legacy_versions = next(iter(versions)).fetch_legacy_versions()
    if legacy_versions:
        print(f'✅ Legacy archive validated')

    warnings = []

    for version in versions:
        try:
            version.process_version(legacy_versions.pop(0) if legacy_versions else None)
        except Exception as e:
            raise VerifyException(f'Failed processing version {version.version_dir.name}: {e}')

        for checked_file in version.checked_files:
            all_files.discard(checked_file)

        for version_file in version.checked_version_files:
            all_files.discard(version.version_dir.joinpath(version_file))

        all_files.discard(version.version_dir)

        warnings.extend(version.warnings)

    all_files.discard(versions_dir)
    all_files.discard(files_dir)
    all_files.discard(old_files_dir)

    if all_files:
        unexpected_files = [str(f.relative_to(zip_dir_path)) for f in all_files]
        warn = f"Found unexpected files in the archive. These are NOT valid parts of the certificate: " \
               f"{unexpected_files}"
        print(f"⚠️ {warn}")
        warnings.append(warn)

    print()
    if warnings:
        print(f"⚠️ There were {len(warnings)} warnings")
    else:
        print(f'✅ Certificate passed all checks')

    return warnings


class Version:
    def __init__(self, version_dir: Path, files_dir: Path, old_files_dir: Path):
        self.version_dir = version_dir
        self.old_files_dir = old_files_dir
        self.files_dir = files_dir
        self.metadata_file = self.version_dir.joinpath('metadata.json')
        self.metadata_json = load_json(self.metadata_file)
        self.checked_files = set()
        self.checked_version_files = set()
        self.warnings = []
        self.successes = []
        self.infos = []
        self.legacy_version = None
        self.private_signatures = set()
        self.files_in_manifest = set()

    def process_version(self, legacy_version):
        print(f'Version {self.version_dir.name}:')
        self.legacy_version = legacy_version

        self.check_manifest()
        self.check_open_timestamp()
        self.check_owner()
        self.check_public_signatures()
        self.check_owner_signature()
        self.check_transferrer_signature()
        self.check_public_files()
        self.check_private_files()
        self.check_private_fields()
        self.check_additional_files()
        self.check_legacy_archive()

    def check_manifest(self):
        manifest_json = load_json(self.version_dir.joinpath('manifest.json'))

        for filename, sha256_base64 in manifest_json.items():
            file = self.version_dir.joinpath(filename)
            if file.exists():
                if sha256sum(file) != sha256_base64:
                    raise VerifyException(f'SHA256 mismatch for file {file}. Expected {sha256_base64}')
                self.files_in_manifest.add(filename)

        for core_file in {'metadata.json', 'metadata.json.sig'}:
            if core_file not in self.files_in_manifest:
                raise VerifyException(f'Core file `{core_file}` was missing')

        self.checked_version_files.add('manifest.json')
        self.checked_version_files.add('metadata.json')

    def check_open_timestamp(self):
        manifest = self.version_dir.joinpath('manifest.json')
        migration_ots = self.version_dir.joinpath('MIGRATION_TIME_manifest.json.ots')
        regular_ots = self.version_dir.joinpath('manifest.json.ots')
        pending_ots = self.version_dir.joinpath('manifest.json.ots.pending')

        if migration_ots.is_file():
            ots_file = migration_ots
            migrated = True
        elif regular_ots.is_file():
            ots_file = regular_ots
            migrated = False
        elif pending_ots.is_file():
            self._warning(f"Open Timestamp not yet added to Bitcoin blockchain")
            self.checked_version_files.add(pending_ots)
            return
        else:
            raise VerifyException('No OTS file found')

        block, block_date = check_open_timestamp_from_file(manifest, ots_file)
        version_datetime = parse_iso_datetime(self.metadata_json['created'])

        if not migrated:
            use_block_date = block_date
        else:
            if self.legacy_version:
                _, _, _, use_block_date = self.legacy_version
            else:
                # Verifying an anonymous legacy certificate
                use_block_date = None

        if use_block_date:
            if version_datetime.date() != use_block_date:
                raise VerifyException(f"OTS date {block_date} didn't match date in version: {version_datetime.date()}")
            self._success(f'Open Timestamp matches date {use_block_date} in block {block}')
        else:
            self._info(f'Open Timestamp matches date of format upgrade {block_date} in block {block}')

        self.checked_version_files.add(ots_file)

    def check_owner(self):
        entry = self._get_private_entry('owner')
        if entry:
            self._success(f'Owner verified as email "{entry.get("email", "")}" and name "{entry.get("name", "")}"')
        else:
            self._info(f'Owner information not present')

    def check_public_signatures(self):
        """
        Checks the public signatures stored in the `signedBy` field.
        These are only used for the master Verisart signature, and for Artist signatures.
        """
        signed_bys = self.metadata_json['signedBy']

        verisart_key_found = False
        for signed_by in signed_bys:
            public_key = signed_by['publicKey']
            signature_filename = signed_by['fileName']
            key_type = signed_by['type']
            if key_type == 'VERISART':
                if public_key != _get_verisart_public_key():
                    raise VerifyException('Incorrect Verisart master public key found')
                verisart_key_found = True
                debug_name = 'Verisart'
            elif key_type == 'ARTIST':
                artists = self.metadata_json['public'].get('artists')
                if not artists:
                    raise VerifyException('No artist ID found')

                debug_name = f'Artist "{format_artist_details(artists[0])}"'

                artist_id = artists[0]['id']  # At the time of writing, artists is always length 1
                artist_key_found = _get_artist_public_key(artist_id)
                if public_key != artist_key_found:
                    raise VerifyException(f'Incorrect Artist public key found. Expected {public_key} but got '
                                          f'{artist_key_found}')
            else:
                self._warning(f"Found unexpected public signature of type {key_type}")
                debug_name = key_type

            if signature_filename not in self.files_in_manifest:
                raise VerifyException(f'Signature file {signature_filename} not in manifest.json')

            signature_file = self.version_dir.joinpath(signature_filename)

            check_signature(self.metadata_file, signature_file, public_key)

            self.checked_version_files.add(signature_filename)

            self._success(f'Signed by {debug_name} {public_key}')

        if not verisart_key_found:
            raise VerifyException('Verisart signature was missing')

    def check_owner_signature(self):
        entry = self._get_private_entry('ownerKey')
        if not self._check_private_signature(entry, self.files_in_manifest, 'Owner'):
            self._info(f'Owner key information not present')

    def check_transferrer_signature(self):
        entry = self._get_private_entry('transferrerKey')
        self._check_private_signature(entry, self.files_in_manifest, 'Transferrer')

    def check_public_files(self):
        self._process_files(self.metadata_json['publicFiles'])

    def check_private_files(self):
        entry = self._get_private_entry('privateFiles')
        if entry:
            self._process_files(entry['files'])
        else:
            self._info(f'Private files information not present')

    def check_private_fields(self):
        entry = self._get_private_entry('privateFields')
        if entry:
            self._success(f'Private fields in `privateFields.json` are valid')
        else:
            self._info(f'Private fields information not present')

    def check_additional_files(self):
        if self.version_dir.joinpath('README.txt').is_file():
            self._info(f'Found file README.txt which is informational only and not part of the verified certificate')
            self.checked_version_files.add('README.txt')

    def check_legacy_archive(self):
        legacy = self.metadata_json['public'].get('legacy', None)
        if legacy:
            if not self.legacy_version:
                # Legacy versions are not included in anonymous archives
                return

            _, valid_public_keys, _, _ = self.legacy_version

            for legacy_pk in valid_public_keys:
                if legacy_pk not in self.private_signatures:
                    raise VerifyException(f'Failed to find matching public key {legacy_pk} in legacy zip in archive')

    def fetch_legacy_versions(self):
        """
        Finds all the legacy versions which are stored as a private file in `legacy_archive.zip`
        """
        if 'legacy' not in self.metadata_json['public']:
            return

        entry = self._get_private_entry('privateFiles')
        if entry:
            matches = [_ for _ in entry['files'] if _['label'] == 'legacy_archive.zip']
            if not matches:
                raise VerifyException('Expected to find legacy_archive.zip')
            filename = matches[0]['fileName']
            file = self.files_dir.joinpath(filename)
            if not file.is_file():
                file = self.old_files_dir.joinpath(filename)

            return check_legacy_archive_version_zip(file)

    def _get_private_entry(self, entry_name: str):
        """
        Returns and validates a private entry file. Private entry files are stored in their own file
        (and are selectively redacted from an archive depending on permissions). Their validity is checked by using the
        `private` field in the `metadata.json` file
        """
        entry_file = self.version_dir.joinpath(f"{entry_name}.json")
        if entry_file.is_file():
            if sha256sum(entry_file) != self.metadata_json['private'][entry_name]['hash']:
                raise VerifyException(f'{entry_name}.json hash did not match expected')

            self.checked_version_files.add(f'{entry_name}.json')

            return load_json(entry_file)

    def _check_private_signature(self, entry: dict, files_in_manifest: set[str], debug_type: str):
        if entry:
            public_key = entry['publicKey']
            signature_file = entry['fileName']

            if signature_file not in files_in_manifest:
                raise VerifyException(f'Signature file {signature_file} not in manifest.json')

            check_signature(self.metadata_file, self.version_dir.joinpath(signature_file), public_key)
            self._success(f'Signed by {debug_type} {public_key}')
            self._info(f'Verify independently if {debug_type} key {public_key} matches the expected owner')

            self.checked_version_files.add(signature_file)
            self.private_signatures.add(public_key)
            return True

    def _process_files(self, files_json: list[dict]):
        for public_file in files_json:
            file_name = public_file['fileName']

            file = self.files_dir.joinpath(file_name)

            if not file.is_file():
                file = self.old_files_dir.joinpath(file_name)

            if sha256sum(file) != public_file['hash']:
                raise VerifyException(f'SHA256 mismatch for file {file_name}. Expected {public_file["hash"]}')

            self.checked_files.add(file)

    def _warning(self, msg: str):
        self.warnings.append(msg)
        print(f"\t⚠️ {msg}")

    def _success(self, msg: str):
        self.successes.append(msg)
        print(f"\t✅ {msg}")

    def _info(self, msg: str):
        self.infos.append(msg)
        print(f"\tℹ️ {msg}")


def _get_verisart_public_key() -> str:
    response = requests.get(f"{API_URL}/key")
    response.raise_for_status()
    key_from_api = response.json()[0]['publicKeySecp']
    if key_from_api != VERISART_PUBLIC_KEY:
        raise VerifyException("Verisart master public key didn't match")
    return key_from_api


def _get_artist_public_key(artist_id: str) -> str:
    response = requests.get(f"{API_URL}/artist/{artist_id}")
    response.raise_for_status()
    artist_public_key = response.json()['publicKeySecp']
    return artist_public_key

