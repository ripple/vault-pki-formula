{% set event_data = data.get('data') %}

start_new_cert_orchestra:
  runner.state.orchestrate:
    - mods: orch.vault_pki_orch
    - pillar:
        # necessary to encode data as json to avoid escaping
        event_data: {{ event_data | json() }}
        event_target: {{ data['id'] }}
