#!/usr/bin/env bash

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=$(cat /srv/vault/.vault-token)
export ROLE_ID=$(vault read auth/approle/role/test-pki/role-id | grep role_id | awk '{print $2}')

apt-get install -y libffi-dev libssl-dev python-dev python-pip
pip install PyYAML hvac cryptography

cat >> /etc/salt/master <<EOF
fileserver_backend:
  - roots

pillar_roots:
  base:
    - /srv/pillar

file_roots:
  base:
    - /srv/salt
    - /srv/formulas/vault-pki-formula

runner_dirs:
  - /srv/runners/salt-runner-vault-pki

vault_pki_runner:
    vault_secret_id_file: /etc/vault-pki-secret-id
    url: http://localhost:8200
    pki_path: /v1/pki/sign/default-role
    role_id: $ROLE_ID
    vault_pki_overrides_file: salt://vault_pki_overrides.yml
    validity_period: 720h

reactor:
  - request/sign:
    - salt://reactor/vault_pki_reactor.sls
EOF

cat > /srv/salt/vault_pki_overrides.yml << EOF
'E@www[0-9].example.com':
  alt_names:
    - www.example.com
    - example.com
    - blog.example.com

'my-vault.example.com':
  ttl: 8760h

'something.example.com':
  ipsans: True
EOF

systemctl restart salt-master
