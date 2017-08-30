{% set event_data = data.get('data') %}

revoke_old_cert:
  salt.runner:
    - name: vault_add_cert_crl.main
    - pillar:
        # necessary to encode data as json to avoid escaping
        event_data: {{ event_data | json() }}
        event_target: {{ data['id'] }}
    - kwargs:
      host: {{ event_target }}
      serialNum: {{ event_data['serialNum'] }}
      mount: {{ event_data['mount'] }}


