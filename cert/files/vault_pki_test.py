"""Unit tests for vault_pki client."""

import logging
import os
import platform
import unittest

from mock_salt import fake_salt
from pyfakefs import fake_filesystem_unittest

import vault_pki


logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


class TestActivate(fake_filesystem_unittest.TestCase):

    def setUp(self):
        self.setUpPyfakefs()
        self.fqdn = platform.node()
        self.uid = os.getuid()
        self.gid = os.getgid()

        # setup base directory structure
        vault_pki.setup_directories(
            vault_pki.BASE_DIR,
            self.fqdn,
            vault_pki.DIR_MODE,
            self.uid,
            self.gid
        )

        # variables to construct cert/key version paths
        format_settings = {'base': vault_pki.BASE_DIR, 'fqdn': self.fqdn}
        self.archive_dir = vault_pki.ARCHIVE_DIR.format(**format_settings)
        self.key_dir = vault_pki.KEY_DIR.format(**format_settings)
        self.live_dir = vault_pki.LIVE_DIR.format(**format_settings)

        # known non-existent version
        self.known_missing_version = '0005'

        # setup key/cert versions
        self.versions = []
        for _ in range(2):
            version = vault_pki.create_new_version_dir(
                    [self.archive_dir, self.key_dir],
                    vault_pki.DIR_MODE,
                    self.uid,
                    self.gid
            )
            self.versions.append(version)
            new_key_dir = os.path.join(self.key_dir, version)
            new_archive_dir = os.path.join(self.archive_dir, version)
            self.fs.CreateFile(
                os.path.join(new_key_dir, vault_pki.KEY_FILENAME)
            )
            self.fs.CreateFile(
                os.path.join(new_key_dir, vault_pki.PKCS8_KEY_FILENAME)
            )
            self.fs.CreateFile(
                os.path.join(new_archive_dir, vault_pki.CERT_FILENAME)
            )
            self.fs.CreateFile(
                os.path.join(new_archive_dir, vault_pki.FULLCHAIN_FILENAME)
            )
        logger.info('Versions available: %s', self.versions)

    def tearDown(self):
        pass

    def testCurrentVersionStartsEmpty(self):
        self.assertEqual(vault_pki._get_current_version(self.live_dir), None)

    def testActivate(self):
        set_version = vault_pki._activate_version_with_rollback(
            self.versions[0],
            self.live_dir
        )
        found_version = vault_pki._get_current_version(self.live_dir)
        self.assertEqual(found_version, set_version)

    def testActivateRollback(self):
        # first set a known good version
        set_version = vault_pki._activate_version_with_rollback(
            self.versions[0],
            self.live_dir
        )
        # then try to set a known non-existent version
        set_version = vault_pki._activate_version_with_rollback(
            self.known_missing_version,
            self.live_dir
        )
        found_version = vault_pki._get_current_version(self.live_dir)
        self.assertEqual(found_version, set_version)

    def testActivateBrokenRollsBack(self):
        # first set a known good version
        set_version = vault_pki._activate_version_with_rollback(
            self.versions[0],
            self.live_dir
        )
        # then *break* the newer version
        new_version = vault_pki._get_version_assets(
            self.versions[1],
            self.fqdn,
            base_dir=vault_pki.BASE_DIR
        )
        cert, chain, key, pkcs8_key = new_version
        os.remove(cert)
        os.remove(chain)
        # attempt to activate the now broken version
        set_version = vault_pki._activate_version_with_rollback(
            self.versions[1],
            self.live_dir
        )
        found_version = vault_pki._get_current_version(self.live_dir)
        self.assertEqual(found_version, set_version)


if __name__ == '__main__':
    unittest.main()
