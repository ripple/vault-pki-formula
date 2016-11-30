# -*- coding: utf-8 -*-
# vim: set ft=sls :

include:
  - python.pip

install crypto dependencies:
  pkg.installed:
    - pkgs:
      - python-dev
      - libssl-dev
      - libffi-dev

install python cryptography module:
  pip.installed:
    - name: cryptography
    - reload_modules: true
    - require:
      - cmd: install_pip2

/usr/local/bin/vault_pki:
  file.managed:
    - source: salt://cert/files/vault_pki.py
    - user: root
    - group: root
    - mode: 755

checkgen_cert:
  cron.present:
    - name: /usr/local/bin/vault_pki checkgen
    - identifier: checkgen_cert
    - user: root
    - special: '@daily'
    - require:
      - file: /usr/local/bin/vault_pki
