{% set event_data = data.get('data') %}

revoke_old_cert:
  runner.vault_add_cert_crl.main:
    - host: demo-minion.ops.ripple.com
    - pillar:
        # necessary to encode data as json to avoid escaping
        event_data: {{ event_data | json() }}
    - serialNum: event_data
    - mount: event_data['data]['mount']


