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

activate_new_version:
  salt.state:
    - tgt: {{ target }}
    - sls:
      - cert.react_activate_cert
    - pillar:
        # beware version being converted to a number
        version: "{{ payload['version'] }}"
    - require:
      - salt: push_signed_cert
