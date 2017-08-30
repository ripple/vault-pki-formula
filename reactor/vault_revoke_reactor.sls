{% set payload = salt.pillar.get('event_data') %}
{% set target = salt.pillar.get('event_target') %}

revoke_old_cert:
  salt.runner:
    - name: vault_add_cert_crl.main
    - kwargs:
      host: {{ target }}
      serialNum: {{ payload['serialNum'] }}
      mount: {{ payload['mount'] }}


