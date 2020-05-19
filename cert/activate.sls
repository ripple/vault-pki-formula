# -*- coding: utf-8 -*-
#
#   Copyright 2018 Ripple Labs, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# vim: set ft=sls :

{% set vault_pki_timeout = salt['pillar.get']('vault_pki:timeout', '600') %}

run vault_pki:
  cmd.run:
    - name: /usr/local/bin/vault_pki checkgen --timeout {{ vault_pki_timeout }}
    - unless: /usr/local/bin/vault_pki checkvalid
    - require:
      - group: setup new cert-access group
      - pkg: install crypto dependencies
      - pip: install python cryptography module
      - file: /usr/local/bin/vault_pki


checkgen_cert:
  cron.present:
    {% if 'prod' in grains['fqdn'] or 'staging' in grains['fqdn'] %}
    - name: (/usr/local/bin/vault_pki list ; /usr/local/bin/vault_pki checkgen --timeout {{ vault_pki_timeout }}; /usr/local/bin/vault_pki list) 2>&1 | tee -a /var/log/cron.log | logger -t vault_pki
    {% else %}
    - name: (/usr/local/bin/vault_pki list ; /usr/local/bin/vault_pki checkgen --timeout {{ vault_pki_timeout }}; /usr/local/bin/vault_pki list) 2>&1 | logger -t vault_pki
    {% endif %}
    - identifier: checkgen_cert
    - user: root
    - hour: random
    - minute: random
    - require:
      - file: /usr/local/bin/vault_pki
