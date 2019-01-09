#!/usr/bin/env bats

@test "Applying salt state 'cert' to minion1 results in no errors"
  run salt 'minion1' state.apply cert
  [ "$status" -eq 0 ]
}
