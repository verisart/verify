import unittest
from pathlib import Path
from unittest.mock import patch

from verisartverify.verify import verify_path, VerifyException

dir = Path('./test-archives')
failed_dir = Path('./test-failed-archives')


class TestVerify(unittest.TestCase):
    def test_valid_certs(self):
        for f in dir.iterdir():
            print('------------------------------------------')
            print(f'Testing {f}')

            warnings = verify_path(f)
            if 'no-ots' not in f.name:
                self.assertEqual([], warnings)
            else:
                for warn in warnings:
                    self.assertIn('Open Timestamp not yet added to Bitcoin blockchain', warn)

    def test_wrong_ots_file(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-ots.zip'))
        self.assertIn('Failed to find success message in OTS output', str(cm.exception))
        self.assertIn('No valid file', str(cm.exception))

    def test_invalid_manifest(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-manifest.zip'))
        self.assertIn('Failed to find success message in OTS output', str(cm.exception))
        self.assertIn('File does not match original', str(cm.exception))

    def test_invalid_metadata(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-metadata.zip'))
        self.assertIn('SHA256 mismatch for file', str(cm.exception))
        self.assertIn('metadata.json', str(cm.exception))

    def test_invalid_public_file(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-public-file.zip'))
        self.assertIn('SHA256 mismatch for file chiWiZAcQvZLWxjCPZj-HAXlzPD4MuljDNk_uCxuPRw.png', str(cm.exception))

    # Private files

    def test_invalid_private_files_json(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-private-files-json.zip'))
        self.assertIn('privateFiles.json hash did not match expected', str(cm.exception))

    def test_invalid_private_file(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-private-file.zip'))
        self.assertIn('SHA256 mismatch for file 6BZG4b7bPLt3UxyGpRRgIkHnVBipmSblEulJmp15SMI.txt', str(cm.exception))

    # Private fields

    def test_invalid_private_fields_json(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-private-fields.zip'))
        self.assertIn('privateFields.json hash did not match expected', str(cm.exception))

    # Owner

    def test_invalid_private_owner_json(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-owner-json.zip'))
        self.assertIn('owner.json hash did not match expected', str(cm.exception))

    # Owner signature

    def test_invalid_private_owner_key_json(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-owner-key-json.zip'))
        self.assertIn('ownerKey.json hash did not match expected', str(cm.exception))

    def test_invalid_private_owner_key_sig_bad_hash(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-private-owner-key-sig.zip'))
        self.assertIn('SHA256 mismatch for file', str(cm.exception))
        self.assertIn('OWNER_VM_metadata.json.sig', str(cm.exception))

    def test_invalid_private_owner_key_sig_bad_signature(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-private-owner-key-sig-wrong.zip'))
        self.assertIn('Failed check_signature in signature file', str(cm.exception))
        self.assertIn('OWNER_VM_metadata.json.sig', str(cm.exception))

    # Transferrer signature

    def test_invalid_private_transferrer_key_json(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-private-transferrer-key-json.zip'))
        self.assertIn('transferrerKey.json hash did not match expected', str(cm.exception))

    def test_invalid_private_transferrer_key_sig_bad_hash(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-private-transferrer-key-sig.zip'))
        self.assertIn('SHA256 mismatch for file', str(cm.exception))
        self.assertIn('OWNER_KEY_CHANGE_VM_metadata.json.sig', str(cm.exception))

    def test_invalid_private_transferrer_key_sig_bad_signature(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-private-transferrer-key-sig-wrong.zip'))
        self.assertIn('Failed check_signature in signature file', str(cm.exception))
        self.assertIn('OWNER_KEY_CHANGE_VM_metadata.json.sig', str(cm.exception))

    # Artist signature

    def test_invalid_artist_sig_bad_hash(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-artist-sig.zip'))
        self.assertIn('SHA256 mismatch for file', str(cm.exception))
        self.assertIn('ARTIST_metadata.json.sig', str(cm.exception))

    def test_invalid_artist_sig_bad_signature(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-artist-sig-wrong.zip'))
        self.assertIn('Failed check_signature in signature file', str(cm.exception))
        self.assertIn('ARTIST_metadata.json.sig', str(cm.exception))

    # Verisart signature

    def test_verisart_sig_bad_hash(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-verisart-sig.zip'))
        self.assertIn('SHA256 mismatch for file', str(cm.exception))
        self.assertIn('metadata.json.sig', str(cm.exception))

    def test_verisart_sig_bad_signature(self):
        with self.assertRaises(VerifyException) as cm:
            verify_path(failed_dir.joinpath('mismatch-verisart-sig-wrong.zip'))
        self.assertIn('Failed check_signature in signature file', str(cm.exception))
        self.assertIn('metadata.json.sig', str(cm.exception))

    # Other tests

    @patch('verisartverify.verify._get_verisart_public_key', return_value="wrongkey")
    def test_wrong_verisart_key(self, _get_verisart_public_key):
        with self.assertRaises(VerifyException) as cm:
            verify_path(dir.joinpath('example-owned.zip'))
        self.assertIn('Incorrect Verisart master public key found', str(cm.exception))

    @patch('verisartverify.verify._get_artist_public_key', return_value="wrongkey")
    def test_wrong_artist_key(self, _get_verisart_public_key):
        with self.assertRaises(VerifyException) as cm:
            verify_path(dir.joinpath('example-owned.zip'))
        self.assertIn('Incorrect Artist public key found', str(cm.exception))

    def test_unexpected_files_in_zip(self):
        warnings = verify_path(failed_dir.joinpath('unexpected-files.zip'))
        self.assertEqual(1, len(warnings))
        warning = warnings[0]

        self.assertIn("Found unexpected files in the archive", warning)
        self.assertIn("unexpected-file", warning)
        self.assertIn("versions/unexpected-file2", warning)
        self.assertIn("files/unexpected-file3", warning)


if __name__ == '__main__':
    unittest.main()
