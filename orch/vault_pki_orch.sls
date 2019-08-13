{% set payload = salt.pillar.get('event_data') %}
{% set target = salt.pillar.get('event_target') %}

push_signed_cert:
  salt.runner:
    - name: vault_pki.main
    - kwargs:
      host: {{ target }}
      csr: |
        {{ payload['csr']|indent(8, false) }}
      path: {{ payload['path'] }}
