#!/bin/sh
# Phase 2 entry point: plant the fake credentials, then run the driver under
# strace. strace writes to this container's stdout (a pipe to the runner);
# everything the package runs is a child of the driver, whose own stdio is
# piped, so package output can't mix into the trace.
set -e
node /opt/specter/plant.mjs
exec strace -f -qq -o /dev/stdout -s 512 -e trace=%network,%file,%process \
  node /opt/specter/driver.mjs "$@"
