"""Unit tests for vault_pki client."""

import logging
import os
import platform
import stat
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from mock_salt import fake_salt
from pyfakefs import fake_filesystem_unittest

import vault_pki


logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())

FAKE_SCRIPT_FILE = 'test_post_activate.sh'
FAKE_SCRIPT_MODE = 0o755
FAKE_SCRIPT_BODY = '''#!/bin/bash
echo hello world
'''
FAKE_SCRIPT_OUTPUT = 'hello world\n'
FAKE_NONSCRIPT_FILE = 'not_executable.sh'
FAKE_NONSCRIPT_MODE = 0o644


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
        self.post_activate_dir = vault_pki.POST_ACTIVATE_DIR.format(
            **format_settings
        )

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

        # create dummy post-activate script
        script_mode = stat.S_IFREG | FAKE_SCRIPT_MODE
        self.fs.CreateFile(
            os.path.join(self.post_activate_dir, FAKE_SCRIPT_FILE),
            st_mode=script_mode,
            contents=FAKE_SCRIPT_BODY
        )
        # create non-executable file, which should be ignored
        nonscript_mode = stat.S_IFREG | FAKE_NONSCRIPT_MODE
        self.fs.CreateFile(
            os.path.join(self.post_activate_dir, FAKE_NONSCRIPT_FILE),
            st_mode=nonscript_mode
        )


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

    @mock.patch('vault_pki.subprocess')
    def testPostActivateScriptRun(self, subprocess_mock):
        p_mock = mock.Mock()
        subprocess_mock.Popen.return_value = p_mock
        p_mock.communicate.return_value = (FAKE_SCRIPT_OUTPUT, '')

        cmd = os.path.join(self.post_activate_dir, FAKE_SCRIPT_FILE)
        activate_scripts = vault_pki.get_post_activate_scripts()
        self.assertListEqual([cmd], activate_scripts)

        _, stdout, _ = vault_pki.run_post_activate_script(cmd)
        self.assertEqual(FAKE_SCRIPT_OUTPUT, stdout)


if __name__ == '__main__':
    unittest.main()
