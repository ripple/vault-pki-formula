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

{% set os_family = grains['os_family'] -%}
{% set vault_pki_timeout = salt['pillar.get']('vault_pki:timeout', '600') %}

include:
  - python.pip

setup new cert-access group:
  group.present:
    - name: cert-access

install crypto dependencies:
  pkg.installed:
    - pkgs:
{% if os_family == 'Debian' %}
      - python-dev
      - libssl-dev
      - libffi-dev
{% elif os_family == 'RedHat' %}
      - python-devel
      - libffi-devel
      - openssl-libs
{% endif -%}

install python cryptography module:
  pip.installed:
    - name: cryptography
{% if os_family == 'Debian' %}
    - bin_env: /usr/local/bin/pip2
{% elif os_family == 'RedHat' %}
    - bin_env: /usr/bin/pip2
{% endif %}
    - reload_modules: true
    - require:
      - pkg: python2-pip

/usr/local/bin/vault_pki:
  file.managed:
    - source: salt://cert/files/vault_pki.py
    - user: root
    - group: root
    - mode: 0755

