# Ubuntu 14.04 has pip 1.5.4, which has a known bug with salt 2015.8.7
# https://github.com/saltstack/salt/issues/28036
# We install the latest pip via easy_install, instead of apt

{%- set python = salt['pillar.get']('python', []) %}
{%- set proxy_url = salt['pillar.get']('proxy_url', None) %}

python_packages:
  pkg.installed:
    - pkgs:
      - python
      - python-setuptools
      {%- if salt['grains.get']('os_family') == 'Debian' %}
      - python3
      - python3-setuptools
      {%- elif salt['grains.get']('os_family') == 'RedHat' %}
      - epel-release
      - python34
      - python34-setuptools
      {%- endif %}

{%- if (salt['grains.get']('lsb_distrib_release') == '18.04' and salt['grains.get']('lsb_distrib_id') == 'Ubuntu') %}
python2-pip:
  pkg.installed:
    - pkgs:
      - python-pip
      - python3-pip

install_pip2:
  cmd.run:
    - name: echo 'This is for you, vault_pki <3'
    - require:
      - pkg: python2-pip

{%- else %}
purge_pip:
  pkg.removed:
    - pkgs:
      - python-pip
      {%- if salt['grains.get']('os_family') == 'Debian' %}
      - python-pip-whl
      - python3-pip
      - python3-pip-whl
      {%- endif %}

install_pip2:
  cmd.run:
    - name: easy_install pip==9.0.3
    {%- if salt['grains.get']('os_family') == 'Debian' %}
    - unless: test -x /usr/local/bin/pip2 -a $(pip --version| awk {'print $2'}) = "9.0.3"
    {%- elif salt['grains.get']('os_family') == 'RedHat' %}
    - unless: test -x /usr/bin/pip2 -a $(pip --version| awk {'print $2'}) = "9.0.3"
    {%- endif %}
    {%- if proxy_url %}
    - env:
      - http_proxy: {{ proxy_url }}
      - https_proxy: {{ proxy_url }}
    {%- endif %}
    - reload_modules: true
    - require:
      - pkg: python_packages
      - pkg: purge_pip

# Dummy to match "python2-formula" FL/OSS formula for
# making compatible requisites in "vault-pki-formula"..
python2-pip:
  pkg.installed:
    - name: python
    - require:
      - cmd: install_pip2

install_pip3:
  cmd.run:
    {%- if salt['grains.get']('os_family') == 'Debian' %}
    - name: easy_install3 pip
    - unless: test -x /usr/local/bin/pip3
    {%- elif salt['grains.get']('os_family') == 'RedHat' %}
    - name: easy_install-3.4 pip
    - unless: test -x /usr/bin/pip3
    {%- endif %}
    {%- if proxy_url %}
    - env:
      - http_proxy: {{ proxy_url }}
      - https_proxy: {{ proxy_url }}
    {%- endif %}
    - reload_modules: true
    - require:
      - pkg: python_packages
      - pkg: purge_pip

# Point pip to our local proxy cache/custom server
{%- if python or proxy_url %}
/etc/pip.conf:
  file.managed:
    - source: salt://python/files/pip.conf.jinja
    - makedirs: true
    - template: jinja
{%- endif %}

{%- endif %} # if (salt['grains.get']('lsb_distrib_release') == '18.04' and salt['grains.get']('lsb_distrib_id') == 'Ubuntu')
