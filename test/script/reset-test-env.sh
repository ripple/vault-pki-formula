#!/usr/bin/env bash

vagrant snapshot restore master bootstrapped-test --no-provision
vagrant snapshot restore minion1 bootstrapped-test --no-provision
