# Vault PKI Formula

A SaltStack formula to issue and automatically update and distribute
certificates from a private certificate authority backed by
[Hashicorp Vault](https://www.vaultproject.io/).

Server-side installation and operation is covered in the documentation
for the [Vault PKI Runner](https://github.com/ripple/salt-runner-vault-pki).
This formula requires the associated Vault PKI Runner to be installed on
the Salt master to operate.


## Overview of Operation

Below is an overview of the operation of the client-side (minion-side)
functionality of Vault PKI.

Events from the minion perspective, *during first application*, in order:
1. ```cert``` state installs client at ```/usr/local/bin/vault_pki```
2. ```cert``` state runs ```vault_pki checkgen```  which creates the
   ```/etc/vault_pki``` directory structure, generates a CSR and fires a
   Salt event with the CSR and other data to request a signed certificate.
3. Server side magic modifies the CSR and gets it signed, see
   [Vault PKI Runner](https://github.com/ripple/salt-runner-vault-pki/blob/master/README.md)
   docs for details.
4. More server side magic writes the signed certificate to the minion and
   runs the ```react_activate_cert``` state on minion.  The state in turn 
   runs ```vault_pki activate``` with the new certificate version.
5. Activation ensures the key, signed certificate, and full certificate chain
   of the new version are all in place.  Symbolic links in the live directory
   are all updated to the new version or none are.
6. If activation of the new certificate version was successful the
   ```/etc/vault_pki/post-activate.d``` directory is searched for scripts
   with the executable bit set.  Each script is run in turn logging output.


## Usage

Apply the ```cert``` state to minions you wish to receive certificates.
They will receive certificates according to the defaults and overrides
configured on the Salt master (see Vault PKI Runner docs for details).

**TLDR;**
- ```vault_pki checkgen``` is safe to run.  Once up to date certificates
  are in place it simply verifies the certificate age and exits. If the
  certificates are too old, or missing, it requests new ones.
- Minions receive a certificate for their Salt minion id, which should be
  the hostname but make sure your Salt minion deployment agrees. 
- Any SANs or IPSANs you wish to apply must be specified in the Vault
  PKI overrides file on the Salt master (on a hostname or a minion
  pattern basis).
- Validity periods are also determined from a default setting on the Salt
  master, or are overridden in aforementioned overrides file.
- Post-Activation scripts can be setup to kick any server that needs to
  know about a new certificate being delivered.
- Certificates are delivered asynchronously and may take up to 10-15 seconds
  to arrive (```vault_pki checkgen```, currently, does not block and wait
  for them and instead logs the certificate request was sent and exits).

**Always configure servers to use the keys and certificates in the
```/etc/vault_pki/live/$hostname``` directory.**

This ensures when the certificate is updated your server does not
need to be reconfigured (maybe just reloaded/restarted/etc).  (If you
simply *must* copy the key and certificate out of the managed directory
see Note 1).

**Post-Activation**:
To ensure your running servers are informed of a new certificate upon
delivery, create a script to notify your service as desired and place it
in ```/etc/vault_pki/post-activate.d/``` with the executable bit set.

**Important Caveat**: Because the ```cert``` state incorporates
asynchronous behavior it is not currently possible to use it in a
requisite properly. *(e.g. to make the ```nginx``` state require the
```cert``` be applied first -- without which can lead to nginx
starting up and crashing because certificates haven't been delivered yet)*
This is only an issue during the first application of highstate, and
a fix is being worked on.


### Certificate Updates

A cron job is installed on the minion to ensure it checks the freshness
of the certificate once per day -- and will request a new one when the
validity period is 50% past.

For example is a minion is issued a certificate valid for 30 days, on
the 16th day the minion will request a new certificate.

To **force an update sooner**, after say adding a new override, simply run
```vault_pki checkgen --force``` on the minion.


### File + Directory Structure

The directory and file structure for the Vault PKI client was adapted from
the EFF project [Certbot](https://certbot.eff.org/).

|File|Purpose|
|----|-------|
|privkey.pem|Private key in the OpenSSL traditional format.|
|privkey.pkcs8|Private key in PKCS#8 -- frequently used by Java programs.|
|cert.pem|The minion certificate with no intermediate chained certificates.|
|fullchain.pem|Minion certificate with all chained certificates--when in doubt use this file.|

|Directory|Purpose|
|---------|-------|
|/etc/vault_pki|Base directory of Vault PKI client.|
|/etc/vault_pki/live/$hostname|Contains symlinks to active key + certificate version.|
|/etc/vault_pki/archive/$hostname|Contains all versions of certificate material.|
|/etc/vault_pki/archive/$hostname/$version|Certificate material for version X.|
|/etc/vault_pki/keys/$hostname|Contains all version of key material.|
|/etc/vault_pki/keys/$hostname/$version|Key material for version X.|

Version numbers are zero-padded 4 digit numbers, starting at 1.
Example: 0001, 0002, 0003, ...


### Notes

1. If you must copy the key + certificate material out of the Vault PKI
   client directory -- do it in a post-activate script if possible so
   that your server still gets the newest version regularly.
