#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

"""

checkgen

- check for existing directory structure and cert/key
  - create the former if missing

- read existing certificate and request new if validity period > 50% over

activate

- takes an argument of a subdir of cert directory structure and if it is
  valid switches the sym-link

list

- lists available cert/key pairs under directory structure
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'Daniel Wilcox (dwilcox@ripple.com)'

import argparse
import datetime
import grp
import logging
import os
import platform
import re
import stat
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from salt import client as salt_client

OWNER_UID = 0
ACCESS_GROUP = 'cert-access'

BASE_DIR = '/etc/vault_pki'

LIVE_BASE_DIR = '{base}/live'
LIVE_DIR = '{base}/live/{fqdn}'

ARCHIVE_BASE_DIR = '{base}/archive'
ARCHIVE_DIR = '{base}/archive/{fqdn}'

KEY_BASE_DIR = '{base}/keys'
KEY_DIR = '{base}/keys/{fqdn}'

VERSION_DIR_FORMAT = '{:04d}'
VERSION_DIR_REGEX = '^[0-9]{4}$'

# Base dir is inserted at runtime to handle overrides.
DIR_TREE = [
    LIVE_BASE_DIR,
    LIVE_DIR,
    ARCHIVE_BASE_DIR,
    ARCHIVE_DIR,
    KEY_BASE_DIR,
    KEY_DIR,
]

DIR_MODE = 0750
KEY_MODE = 0640

KEY_FILENAME = 'privkey.pem'
CERT_FILENAME = 'cert.pem'
FULLCHAIN_FILENAME = 'fullchain.pem'

DEFAULT_KEY_LENGTH = 2048

SALT_EVENT_TAG = 'request/sign'

logger = logging.getLogger(__name__)


class SetupError(Exception):
    """Exception class for errors during environment setup."""
    pass


class GenerationError(Exception):
    """Exception class for errors during key/CSR generation."""
    pass


def _setup_directory(dir_path, mode, owner_uid, group_gid):
    """Ensure a given directory exists and conforms to expected settings."""
    try:
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path, mode=mode)
            os.chown(dir_path, owner_uid, group_gid)
        else:
            dir_stat = os.stat(dir_path)
            dir_mode = stat.S_IMODE(dir_stat.st_mode)
            if not dir_mode & mode == dir_mode:
                os.chmod(dir_path, mode)
            if not (dir_stat.st_uid == owner_uid and
                    dir_stat.st_gid == group_gid):
                os.chown(dir_path, owner_uid, group_gid)
    except IOError:
        return False
    else:
        return True


def setup_directories(base_dir, fqdn, mode, uid, gid):
    """Setup directory structure needed for cert updating operations."""
    expected_dirs = []
    settings = {'base': base_dir, 'fqdn': fqdn}
    dir_tree = DIR_TREE[:]
    dir_tree.insert(0, base_dir)
    for directory in DIR_TREE:
        expected_dirs.append((directory.format(settings), mode, uid, gid))

    errors = []
    for dir_settings in expected_dirs:
        setup_ok = _setup_directory(*dir_settings)
        if not setup_ok:
            errors.append('Error setting up: {}'.format(dir_settings))
    if errors:
        raise SetupError('\n'.join(errors))


def generate(fqdn, write_dir, key_length, mode, owner_uid, group_gid):
    """Generate a key and CSR for headless operation.

    The private key is written out to the provided directory and
    the CSR is returned as a PEM encoded string.
    """
    public_exp = 65537
    priv_key = rsa.generate_private_key(
        public_exponent=public_exp,
        key_size=key_length,
        backend=default_backend())
    priv_key_filepath = os.path.join(write_dir, KEY_FILENAME)
    try:
        with open(priv_key_filepath, 'w') as keyfile:
            keyfile.write(priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(priv_key_filepath, mode)
        os.chown(priv_key_filepath, owner_uid, group_gid)
    except IOError:
        raise GenerationError('Error writing key file {}'.format(keyfile))
    builder = x509.CertificateSigningRequestBuilder()
    common_name = x509.NameAttribute(
        x509.oid.NameOID.COMMON_NAME,
        fqdn)
    builder = builder.subject_name(x509.Name([common_name]))
    builder = builder.add_extension(x509.BasicConstraints(
        ca=False,
        path_length=None), critical=True)
    csr = builder.sign(priv_key, hashes.SHA256(), default_backend())
    csr_pem_encoded = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem_encoded


def get_version_dirs(version_base_dirs):
    """Get a list of existing version directories installed.

    Walks provided directories for sub-directories matching the version
    directory pattern and returns them.  If inconsistent version
    directories are found an exception is raised.
    """

    def _match_version_dir(v_dir):
        """Match version directories."""
        if re.match(VERSION_DIR_REGEX, v_dir):
            return True
        else:
            return False

    errors = []
    match_values = None
    versions_by_base_dir = {}

    for base_dir in version_base_dirs:
        _, version_dirs, _ = next(os.walk(base_dir))
        versions = [version for version in version_dirs
                    if _match_version_dir(version)]
        versions_by_base_dir[base_dir] = set(versions)

    for base_dir, versions in versions_by_base_dir.items():
        if match_values is None:
            match_values = versions
            continue
        if versions != match_values:
            errors.append('Values from {} ({}) do not match {}'.format(
                base_dir,
                versions,
                match_values))
    if errors:
        raise SetupError(
            'ERROR: Version directories out of sync:\n{}'.format(
                '\n\t'.join(errors))
        )
    return match_values


def create_new_version_dir(version_base_dirs, mode, owner_uid, group_gid):
    """Increment to a new version and create sub-directories.

    Gets a list of version directories, which are numeric, from the
    provided 'base' directories.  Increments the highest version found
    to obtain a new version number and then creates similarly named
    version sub-directories in the provided 'base' directories.
    """
    version_dirs = get_version_dirs(version_base_dirs)
    versions = [int(version) for version in version_dirs]
    if versions:
        new_version = max(versions) + 1
    else:
        new_version = 1
    new_version_str = VERSION_DIR_FORMAT.format(new_version)
    for base_dir in version_base_dirs:
        new_dir = os.path.join(base_dir, new_version_str)
        try:
            os.makedirs(new_dir, mode=mode)
            os.chown(new_dir, owner_uid, group_gid)
        except OSError:
            raise SetupError(
                'Failed to setup new version directory: {}'.format(new_dir)
            )
    return new_version_str


def new_cert_needed(cert_path, refresh_at=0.5):
    """True if a cert is past the percentile through it's validity period.

    Handles the case of no such certificate the same as if it existed
    and needs a refresh.
    """
    get_new_cert = False
    now = datetime.datetime.now()
    if not os.access(cert_path, os.F_OK):
        get_new_cert = True
        logger.info('Cert status: missing.')
    else:
        with open(cert_path, 'r') as certfile:
            cert = x509.load_pem_x509_certificate(
                certfile.read(),
                default_backend())
        validity_period = cert.not_valid_after - cert.not_valid_before
        refresh_offset = datetime.timedelta(validity_period.days * refresh_at)
        refresh_after_date = cert.not_valid_before + refresh_offset
        if now > refresh_after_date:
            get_new_cert = True
            logger.info(
                'Cert status: past refresh-after ({}).'.format(
                    refresh_after_date.isoformat())
            )
    return get_new_cert


def send_cert_request(event_tag, version, csr):
    """Send CSR to the salt master."""
    caller = salt_client.Caller()
    return caller.cmd('event.send', event_tag, version=version, csr=csr)


def checkgen_main(args):
    """Main function for checking and kicking off new cert generation.

    Ensures directory structure looks sane and checks the remaining time
    on the existing cert, if it exists.  If the cert is past the specified
    fraction of it's period of validity, new version directories are created
    and a key and CSR are generated.  The latter is sent to the salt master
    to be signed and returned.  The signed certificate is returned by a salt
    master runner -- not in this program.

    Note: this sub-command does *not* activate the new cert by switching
    symlinks, please see the activate sub-command for that.
    """
    fqdn = platform.node()
    if not fqdn:
        raise SetupError('Missing FQDN!')
    try:
        group_info = grp.getgrnam(ACCESS_GROUP)
        group_gid = group_info.gr_gid
    except KeyError:
        raise SetupError('Missing group: {}'.format(ACCESS_GROUP))
    try:
        setup_directories(BASE_DIR, fqdn, DIR_MODE, OWNER_UID, group_gid)
    except SetupError:
        raise
    archive_dir = ARCHIVE_DIR.format(BASE_DIR, fqdn)
    key_dir = KEY_DIR.format(BASE_DIR, fqdn)
    live_dir = LIVE_DIR.format(BASE_DIR, fqdn)
    cert_path = os.path.join(live_dir, CERT_FILENAME)

    if new_cert_needed(cert_path):
        version_base_dirs = [archive_dir, key_dir]
        new_version = create_new_version_dir(version_base_dirs,
                                             DIR_MODE,
                                             OWNER_UID,
                                             group_gid)
        csr = generate(fqdn,
                       key_dir,
                       DEFAULT_KEY_LENGTH,
                       KEY_MODE, OWNER_UID,
                       group_gid)
        sent_ok = send_cert_request(SALT_EVENT_TAG, new_version, csr)
        if not sent_ok:
            logger.error('Error sending CSR to salt master!')
    else:
        logger.info('Cert Status: OK.')


def setup_logger(logger, interactive=False, default_level=logging.INFO):
    """Setup default logging configuration."""
    #TODO add proper syslog support for non-interactive usage
    logger.setLevel(default_level)
    log_formatter = logging.Formatter(('%(asctime)s - %(name)s - %(levelname)s'
                                       ' - %(message)s'))
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(log_formatter)
    log_handler.setLevel(default_level)
    logger.addHandler(log_handler)


def main():
    parser = argparse.ArgumentParser(prog='vault_pki')
    sub_parsers = parser.add_subparsers(help='sub-command help')

    parser_checkgen = sub_parsers.add_parser('checkgen', help='checkgen help')
    #parser_checkgen.add_argument
    parser_checkgen.set_defaults(main_func=checkgen_main)

    args = parser.parse_args(sys.argv[1:])
    setup_logger(logger)
    try:
        args.main_func(args)
    except AttributeError:
        parser.print_usage()
        sys.exit(1)


if __name__ == '__main__':
    main()
