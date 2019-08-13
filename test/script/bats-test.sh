#!/usr/bin/env bash

CLASS=${1:-master}
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

bats $DIR/../bats/$CLASS/
