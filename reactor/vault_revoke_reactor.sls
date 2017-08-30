{% set event_data = data.get('data') %}

revoke_old_cert:
  salt.runner:
    - name: vault_add_cert_crl.main
    - pillar:
        # necessary to encode data as json to avoid escaping
        event_data: {{ event_data | json() }}
    - kwargs:
      serialNum: event_data


