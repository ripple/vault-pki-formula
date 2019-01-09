# vault-pki-formula Vagrant Test

A test scaffold for testing out vault-pki and formula

# TODO
- Convert from VMs to Docker for testing
- Setup BATS fully

# Instructions

Run the following commands in a terminal. Git, VirtualBox and Vagrant must
already be installed.

```
# Only do this if needed and doing debugging against the salt-runner
# export VAULT_PKI_RUNNER_BRANCH=branch
vagrant plugin install vagrant-vbguest
script/start-test-env.sh
```

This will download an Ubuntu  VirtualBox image and create two virtual
machines for you. One will be a Salt Master named `master` and one will be Salt
Minion named `minion1`. There is also an additional commented-out `minion2` that
can be enabled if needed for testing. The minions will already be pointed to the master.
Master and the Minion's keys will already be accepted. Because the keys are
pre-generated and reside in the repo, do not use this for any production purposes.
These are unsafe!

This script also snapshots the VMs in a functional state

- To see the full cert request cycle happen, run the following command:
```
vagrant ssh master -- sudo salt 'minion1' state.apply cert
```

This should return a successful run with the first certificate setup on minion1.

- Check it out by logging in and looking at the results:
```
ssh vagrant minion1 -- sudo tree /etc/vault_pki
```

- Run it one more time, and notice that it won't request a new cert. Everything's OK! It should run much faster
```
vagrant ssh master -- sudo salt 'minion1' state.apply cert
```

# Debugging

Best way to try things out is to do the following:


Do some testing by logging into either the `master` or `minion1`:

- Master
```
vagrant ssh master

# Command to listen to the salt master bus
$ sudo /vagrant/script/master-event-listen.sh
```

- On the minion
```
vagrant ssh minion1

# Command to listen to the salt master bus
$ sudo /vagrant/script/minion-event-listen.sh
```


