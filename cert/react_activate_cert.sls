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

{% set version = salt['pillar.get']('version') %}

run_activate_command:
  cmd.run:
    - name: /usr/local/bin/vault_pki activate {{ version }}

update_current_file:
  file.managed:
    - name: /etc/vault_pki/live/{{ grains['id'] }}/current
    - mode: 0644
    - user: root
    - group: cert-access
    - contents: "{{ version }}"
    - require:
      - cmd: run_activate_command
