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

include:
  - python.pip

setup new cert-access group:
  group.present:
    - name: cert-access

install crypto dependencies:
  pkg.installed:
    - pkgs:
{% if grains['os_family'] == 'Debian' %}
      - python-dev
      - libssl-dev
      - libffi-dev
{% elif grains['os_family'] == 'RedHat' %}
      - python-devel
      - libffi-devel
      - openssl-libs
{% endif -%}

install python cryptography module:
  pip.installed:
    - name: cryptography
{% if grains['os_family'] == 'Debian' %}
    - bin_env: /usr/local/bin/pip2
{% elif grains['os_family'] == 'RedHat' %}
    - bin_env: /usr/bin/pip2
{% endif %}
    - reload_modules: true
    - require:
      - cmd: install_pip2

/usr/local/bin/vault_pki:
  file.managed:
    - source: salt://cert/files/vault_pki.py
    - user: root
    - group: root
    - mode: 0755

run vault_pki to get initial cert:
  cmd.run:
    - name: /usr/local/bin/vault_pki checkgen
    - require:
      - group: setup new cert-access group
      - pkg: install crypto dependencies
      - pip: install python cryptography module
      - file: /usr/local/bin/vault_pki

checkgen_cert:
  cron.present:
    - name: /usr/local/bin/vault_pki checkgen
    - identifier: checkgen_cert
    - user: root
    - special: '@daily'
    - require:
      - file: /usr/local/bin/vault_pki
