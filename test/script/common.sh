#!/usr/bin/env bash
# DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# source $DIR/common.sh

get_eventlisten() {
  if [ ! -f /tmp/eventlisten.py ];
  then
    wget https://raw.githubusercontent.com/saltstack/salt/develop/tests/eventlisten.py -O /tmp/eventlisten.py
  fi
}

install_python_deps() {
    apt-get install -y libffi-dev libssl-dev python-dev python-pip
    pip install PyYAML hvac cryptography
}
