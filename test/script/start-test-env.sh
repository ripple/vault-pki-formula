#!/usr/bin/env bash

vagrant up
vagrant snapshot save master bootstrapped-test
vagrant snapshot save minion1 bootstrapped-test
