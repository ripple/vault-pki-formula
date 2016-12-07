#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

"""Command for managing a cert issued by way of the salt-master.

This command was written with the intention of the Salt master ferrying
the certificate signing request (CSR) to a Vault PKI backend.  That
functionality is included in a separate Salt runner which is expected to
write the resulting certificate and full certificate chain back onto the
requesting minion.

This command is intended to be used in a headless fashion where it
is run in a cron job, perhaps daily.  'checkgen' is the command to
check the existing certificate and determine if a new one is needed.
By default a new certificate is requested when the issued one is 50%
of the way through it's validity period.

A particular directory tree structure is used, based off of the Certbot
project:

/etc/vault_pki/
           archive/
                   myhostname/
                              0001/
                                   cert.pem
                                   fullchain.pem
           keys/
                myhostname/
                           0001/
                                key.pem
           live/
                myhostname/
                       cert.pem -> <base>/archive/myhostname/0001/cert.pem
                ...

In this example '0001' refers to the first cert/key material version.
And versions are scoped underneath a hostname in the event of hostname
changes or the desire to have multiple certs (not really supported yet).

The 'live' directory under /etc/vault_pki is also scoped by hostname but
contains only symbolic links to the current (live) cert/key and fullchain.


Summary of sub-command operation:

checkgen
    - Check for existing directory structure (/etc/vault_pki) and for a
      current live certificate and key.
    - Create the directory structure if it is missing.
    - If there is an existing certificate check if period remaining is
      less than 50% of the issued valid duration.
        - If the certificate is missing or sufficiently old determine
          a new version number and create new version directories.
        - Generate a key and certificate signing request (CSR), writing
          the former into the new keys version directory.
        - Send the CSR in a Salt event call to the Salt master onward
          to be signed (with a return path to write the certificate at).
    - Otherwise if certificate is in OK, log that and exit.

activate
    - Takes a version number as an argument.
    - If the version number looks like a version number (four digits),
      has existing directories and all of the requisite files, *and*
      those files are readable and the current live directory is
      writable -- then the live symlinks are switched to the specified
      version.
    - If an error occurs during the course of switching *any* symlink
      they will attempt to switch back to the last seen version. This
      is an to maintain a consistent state of the presented key and
      certificate.

lists
    - Prints a list of available cert/key versions and marks the active
      version with a '*'.


Things that could be improved / Ways to help:

    - move logging to syslog/etc when non-interactive
    - unittests!!!
    - more debug logging
    - more traceback logging
    - better logging in general
    - detect when a rollback is a no-operation and skip, for cases
      where the very first symlink switch fails and there are no
      changes to roll back.
    - CLI options, validity period to refresh, write out CSR, base_dir,
      fqdn, verbose, print active version for list, etc.
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

import six

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

DIR_MODE = 0o750
KEY_MODE = 0o640

KEY_FILENAME = 'privkey.pem'
CERT_FILENAME = 'cert.pem'
FULLCHAIN_FILENAME = 'fullchain.pem'

DEFAULT_KEY_LENGTH = 2048

SALT_EVENT_TAG = 'request/sign'

logger = logging.getLogger(__file__)


class ActivationError(Exception):
    """Exception class for errors during new version activation."""
    pass


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
    for directory in dir_tree:
        expected_dirs.append((directory.format(**settings), mode, uid, gid))

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
        six.u(fqdn))
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
                six.b(certfile.read()),
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


def send_cert_request(event_tag, dest_cert_path, csr):
    """Send CSR to the salt master."""
    caller = salt_client.Caller()
    return caller.cmd('event.send',
                      event_tag,
                      csr=csr,
                      path=dest_cert_path)


def _atomic_link_switch(source, destination):
    """Does an atomic symlink swap by overwriting the destination symlink.

    Creates a temporary symlink to the source and overwrites the
    destination symlink.  The rename system call is atomic under Linux.
    Uses the current time as a timestamp as the temporary symlink suffix.

    TODO: figure out best way to clean up temp symlinks in the event of
    failure.
    """
    now = datetime.datetime.now()
    swap_suffix = now.strftime('%s')
    temp_destination = '{}-{}'.format(destination, swap_suffix)
    try:
        os.symlink(source, temp_destination)
        os.rename(temp_destination, destination)
    except (OSError, IOError, SystemError):
        raise ActivationError('Failed symlink swap from "{}" to "{}"'.format(
            source, destination))


def _activate_version(version_str, live_dir):
    """Activates a given cert/key version by switching the live symlinks.

    Errors if any of the new version symlinks cannot be swapped in - so
    as to be able to trigger a rollback to a stable version.
    """
    live_key_path = os.path.join(live_dir, KEY_FILENAME)
    live_cert_path = os.path.join(live_dir, CERT_FILENAME)
    live_chain_path = os.path.join(live_dir, FULLCHAIN_FILENAME)
    cert_path, chain_path, key_path = _get_version_assets(version_str)
    try:
        _atomic_link_switch(key_path, live_key_path)
        _atomic_link_switch(cert_path, live_cert_path)
        _atomic_link_switch(chain_path, live_chain_path)
    except ActivationError:
        logger.critical(
            'Failed to activate "{}"!'.format(
                version_str)
        )
        logger.critical(exc_info=True)
        raise


def _activate_version_with_rollback(version_str, live_dir):
    """Activate a cert/key version but rollback to if errors occur.

    Records the current cert/key version before activation and if it
    is sane attempts to restore it in the event of an error occuring.
    """
    rollback_ok = False
    old_version = _get_current_version(live_dir)
    if old_version is not None:
        rollback_ok = True
    else:
        logger.warning(
            'Rollback not possible -- no valid prior version found.'
        )
    def _run_activate(version, live_dir, rollback_ok):
        """Run activation such that rollback has a try/except block."""
        try:
            _activate_version(version, live_dir)
            logger.info('Successfully activated version "{}".'.format(
                version))
        except ActivationError:
            if rollback_ok:
                logger.warning(
                    'Activate raised an error. Rolling back to "{}"'.format(
                        old_version)
                )
                rollback_ok = False
                return _run_activate(old_version, live_dir, rollback_ok)
            else:
                logger.error('Activate raised an uncorrectable error.')
                raise
        else:
            return version
    return _run_activate(version_str, live_dir, rollback_ok)


def _get_current_version(live_dir):
    """Returns the current certificate/key version or None.

    Also returns None in the event of the initial installation of the
    cert in which there is no reasonable rollback.  Inconsistent
    installations, those with many versions, also return None as they
    are presumed broken and not a safe rollback target.
    """
    versions = set()
    missing = set()
    expected_files = {CERT_FILENAME, FULLCHAIN_FILENAME, KEY_FILENAME}
    for filename in expected_files:
        link_path = os.path.join(live_dir, filename)
        try:
            real_path = os.readlink(link_path)
        except OSError:
            logger.debug(
                'Missing or broken symlink from "{}".'.format(link_path)
            )
            missing.add(filename)
            continue
        version_dir = os.path.basename(os.path.dirname(real_path))
        if version_dir:
            versions.add(version_dir)
        else:
            logger.warning(
                'Live file parent directory ({}) is empty string.'.format(
                    real_path)
            )
            continue
    if missing == expected_files:
        logger.info('No live cert/key material, fresh install.')
        return None
    if versions and len(versions) > 1:
        logger.error(
            'Versions >1 or invalid, continuing with no rollback:\n{}'.format(
                '\n'.join(versions))
        )
        return None
    else:
        return versions.pop()


def _get_version_assets(version_str, fqdn=None, base_dir=BASE_DIR):
    """Given a version string fetch the associated key and cert files.

    In the event the specified version directories are not in place, or
    the files readable an ActivationError is thrown.
    """
    path_join = os.path.join
    is_dir = os.path.isdir
    if not fqdn:
        fqdn = platform.node()
    format_settings = {'base': base_dir, 'fqdn': fqdn}
    archive_dir = ARCHIVE_DIR.format(**format_settings)
    key_dir = KEY_DIR.format(**format_settings)
    archive_version_dir = path_join(archive_dir, version_str)
    key_version_dir = path_join(key_dir, version_str)
    if not (is_dir(archive_version_dir) and is_dir(key_version_dir)):
        err = 'Directory tree invalid or missing for version "{}":\n{}'.format(
            version_str,
            '\n'.join([archive_version_dir, key_version_dir]))
        logger.critical(err)
        raise ActivationError(err)
    key_path = path_join(key_version_dir, KEY_FILENAME)
    cert_path = path_join(archive_version_dir, CERT_FILENAME)
    chain_path = path_join(archive_version_dir, FULLCHAIN_FILENAME)
    access_ok = [os.access(path, os.R_OK)
                 for path in (key_path, cert_path, chain_path)]
    if not all(access_ok):
        err = 'Unable to *all* read necessary files:\n{}'.format(
            [key_path, cert_path, chain_path]
        )
        logger.critical(err)
        raise ActivationError(err)
    return (cert_path, chain_path, key_path)


def activate_main(args):
    """Switch the live symlinks for cert/key/chain to the given version.

    Activates a provided version of the cert/key material by switching
    symbolic links - in a gestalt manner as possible.  Including the
    ability to 'rollback' to the last set version if switching any one
    of the symlinks fails.
    """
    version_str = args.version[0]
    if not re.match(VERSION_DIR_REGEX, version_str):
        logger.critical('Invalid version string.')
        sys.exit(1)
    fqdn = platform.node()
    format_settings = {'base': BASE_DIR, 'fqdn': fqdn}
    live_dir = LIVE_DIR.format(**format_settings)
    if not os.access(live_dir, os.W_OK):
        logger.critical(
            'Unable to write to live directory:\n{}'.format(live_dir)
        )
        sys.exit(1)
    set_version = _activate_version_with_rollback(version_str, live_dir)
    logger.info('Set version "{}" to active.'.format(set_version))


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
    format_settings = {'base': BASE_DIR, 'fqdn': fqdn}
    archive_dir = ARCHIVE_DIR.format(**format_settings)
    key_dir = KEY_DIR.format(**format_settings)
    live_dir = LIVE_DIR.format(**format_settings)
    cert_path = os.path.join(live_dir, CERT_FILENAME)

    if new_cert_needed(cert_path):
        version_base_dirs = [archive_dir, key_dir]
        new_version = create_new_version_dir(version_base_dirs,
                                             DIR_MODE,
                                             OWNER_UID,
                                             group_gid)
        new_key_dir = os.path.join(key_dir, new_version)
        csr = generate(fqdn,
                       new_key_dir,
                       DEFAULT_KEY_LENGTH,
                       KEY_MODE, OWNER_UID,
                       group_gid)
        new_archive_dir = os.path.join(archive_dir, new_version)
        sent_ok = send_cert_request(SALT_EVENT_TAG, new_archive_dir, csr)
        if not sent_ok:
            logger.error('Error sending CSR to salt master!')
    else:
        logger.info('Cert Status: OK.')


def list_main(args):
    fqdn = platform.node()
    if not fqdn:
        raise SetupError('Missing FQDN!')
    format_settings = {'base': BASE_DIR, 'fqdn': fqdn}
    archive_dir = ARCHIVE_DIR.format(**format_settings)
    key_dir = KEY_DIR.format(**format_settings)
    live_dir = LIVE_DIR.format(**format_settings)

    current_version = _get_current_version(live_dir)
    for version in sorted(get_version_dirs([archive_dir, key_dir])):
        if version == current_version:
            print('{} *'.format(version))
        else:
            print(version)


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
    """Setup arguments and run main functions for sub-commands."""
    parser = argparse.ArgumentParser(prog='vault_pki')
    sub_parsers = parser.add_subparsers(help='sub-command help')

    parser_checkgen = sub_parsers.add_parser('checkgen', help='checkgen help')
    parser_checkgen.set_defaults(main_func=checkgen_main)

    parser_list = sub_parsers.add_parser('list', help='list help')
    parser_list.set_defaults(main_func=list_main)

    parser_activate = sub_parsers.add_parser('activate', help='activate help')
    parser_activate.add_argument('version',
                                 nargs=1,
                                 help='Version to activate.')
    parser_activate.set_defaults(main_func=activate_main)

    args = parser.parse_args(sys.argv[1:])
    setup_logger(logger)
    try:
        args.main_func(args)
    except AttributeError:
        parser.print_usage()
        sys.exit(1)


if __name__ == '__main__':
    main()
