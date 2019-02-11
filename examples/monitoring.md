# Monitoring Vault-PKI

## Dead simple Prometheus monitoring

This is dependent on your hosts running the node_exporter and then using it
to export metrics on behalf of Vault-PKI runs.

For more info on how to configure the node_exporter to pick-up a directory
full of text file metrics of your choice see:

- [Node Exporter - Textfile Collector](https://github.com/prometheus/node_exporter#textfile-collector)
- [Prometheus Exposition Formats](https://prometheus.io/docs/instrumenting/exposition_formats/)

As part of your node_exporter formula create a directory, say
`/etc/prometheus.d` and create a Vault-PKI post-activate script like so:

```bash
#!/bin/bash

VERSION=$(vault_pki list --active)
UPDATED=$(date +%s)
EXPIRATION=$(vault_pki list --expiration)

cat > /etc/prometheus.d/vault_pki.prom << EOF
# Current vault_pki cert version
# TYPE node_vault_pki_version gauge
node_vault_pki_version ${VERSION}

# Last time vault_pki activate was run
# TYPE node_vault_pki_last_update gauge
node_vault_pki_last_update ${UPDATED}

# Time of expiration of currently active certificate
# TYPE node_vault_pki_cert_expiration gauge
node_vault_pki_cert_expiration ${EXPIRATION}
EOF
```

Now everytime Vault-PKI gets a newly activated version metrics on
your hosts will be updated.
