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

import argparse
import grp
import os
import platform
import stat
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import hvac

OWNER_UID = 0
ACCESS_GROUP = 'cert-access'

BASE_DIR = '/etc/vault_pki'

LIVE_BASE_DIR = '{base}/live'
LIVE_DIR = '{base}/live/{fqdn}'

ARCHIVE_BASE_DIR = '{base}/archive'
ARCHIVE_DIR = '{base}/archive/{fqdn}'

KEY_BASE_DIR = '{base}/keys'
KEY_DIR = '{base}/keys/{fqdn}'

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

KEY_FILENAME = 'privkey.pem'
CERT_FILENAME = 'cert.pem'
FULLCHAIN_FILENAME = 'fullchain.pem'

DEFAULT_KEY_LENGTH = 2048


class SetupError(Exception):
    """Exception class for errors during environment setup."""
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


def generate(fqdn, write_dir, key_length=DEFAULT_KEY_LENGTH):
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
    except IOError:
        raise
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


def get_version_dirs(archive_dir, key_dir):

    def _match_version_dir(v_dir):
        if re.match('^[0-9]{4}$', v_dir):
            return True
        else:
            return False

    _, archive_dirs, _ = next(os.walk(archive_dir))
    _, key_dirs, _ = next(os.walk(key_dir))
    archive_versions = set([version for version in archive_dirs
                            if _match_version_dir(version)])
    key_versions = set([version for version in key_dirs
                        if _match_version_dir(version)])
    if archive_versions ^ key_versions:
        #TODO log something here, directories out of sync
        # maybe exit panic or take highest and go on
        pass
    return list(key_versions | archive_versions)


def create_new_version_dir(archive_dir, key_dir):
    # check to make sure versions are consistent
    # grab newest one per naming pattern, increment it
    # create new version dir in both directories
    version_dirs = get_version_dirs(archive_dir, key_dir)
    versions = [int(version) for version in version_dirs]
    new_version = max(versions) + 1
    new_version_str = '{:04d}'.format(new_version)
    # TODO finish here, makedirs




def new_cert_needed(cert_path):
    get_new_cert = False
    if os.access(cert_path, os.F_OK):
        with open(cert_path, 'r') as certfile:
            cert = x509.load_pem_x509_certificate(
                certfile.read(),
                default_backend())
            # check if cert is 'nearing' expiration
            # probably need an argument like .5 or something here
            #TODO finish here


def checkgen_main(args):
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
    cert_path = os.path.join(LIVE_DIR.format(BASE_DIR, fqdn), CERT_FILENAME)
    if new_cert_needed(cert_path):
        # get new version directories created
        # pass new key dir to generate()
        # kick off request to master w/ csr
        pass
    else:
        # log cert checked and still OK
        pass



def main():
    parser = argparse.ArgumentParser(prog='vault_pki')
    sub_parsers = parser.add_subparsers(help='sub-command help')

    parser_checkgen = sub_parsers.add_parser('checkgen', help='checkgen help')
    #parser_checkgen.add_argument
    parser_checkgen.set_defaults(main_func=checkgen_main)

    args = parser.parse_args(sys.argv[1:])
    try:
        args.main_func(args)
    except AttributeError:
        parser.print_usage()
        sys.exit(1)


if __name__ == '__main__':
    main()
