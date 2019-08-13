#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/common.sh

get_eventlisten
python /tmp/eventlisten.py -n master -i $(hostname -s)
