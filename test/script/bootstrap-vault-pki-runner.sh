#!/usr/bin/env bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=$(cat /srv/vault/.vault-token)
export VAULT_PKI_RUNNER_BRANCH=${VAULT_PKI_RUNNER_BRANCH:-master}

apt-get install -y git jq

# Enable AppRole Authentication + PKI Backend
## Generate Root CA
vault auth-enable approle
vault mount -path=root_ca pki
vault mount-tune -max-lease-ttl=87600h root_ca
vault write root_ca/root/generate/internal common_name="Root CA" ttl=87600h exclude_cn_from_sans=true

## Generate Intermediate CA
vault mount -path=pki pki
vault mount-tune -max-lease-ttl=87600h pki
export CSR=$(vault write pki/intermediate/generate/internal common_name="Intermediate CA" ttl=26280h  exclude_cn_from_sans=true -format=json | jq .data.csr)
echo "$CSR" | sed -e 's/^"//' -e 's/"$//' | awk '{gsub(/\\n/,"\n")}1' > intermediate.csr
export CERT=$(vault write root_ca/root/sign-intermediate csr=@intermediate.csr common_name="Intermediate CA" ttl=8760h -format=json | jq .data.certificate)
echo "$CERT" | sed -e 's/^"//' -e 's/"$//' | awk '{gsub(/\\n/,"\n")}1' > intermediate.crt
vault write pki/intermediate/set-signed certificate=@intermediate.crt

# Limit CSRs signed/issued
vault write pki/roles/default-role allow_any_name=true allow_subdomains=true max_ttl=720h

# Create a permissive policy for use by Vault PKI
cat > vault-pki-policy.hcl << EOF
path "pki/*" {
  policy = "write"
}
EOF

vault policy-write vault_pki vault-pki-policy.hcl

# Create an AppRole for Vault PKI to authenticate to Vault as
vault write auth/approle/role/test-pki policies=vault_pki
export ROLE_ID=$(vault read auth/approle/role/test-pki/role-id | grep role_id | awk '{print $2}')
export SECRET_ID=$(vault write -f auth/approle/role/test-pki/secret-id | grep secret | grep -v accessor | awk '{print $2}')

echo $SECRET_ID > /etc/vault-pki-secret-id
chmod 600 /etc/vault-pki-secret-id

git clone https://github.com/ripple/salt-runner-vault-pki.git /srv/runners/salt-runner-vault-pki -b $VAULT_PKI_RUNNER_BRANCH
