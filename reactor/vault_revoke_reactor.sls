{% set event_data = data.get('data') %}

revoke_old_cert:
  salt.runner:
    - name: vault_add_cert_crl.main
    - kwargs:
      host: {{ target }}
      serialNum: {{ payload['serialNum'] }}
      mount: {{ payload['mount'] }}


