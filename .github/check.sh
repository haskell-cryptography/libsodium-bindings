#!/bin/sh

ormolu_bin=$1

cabal_fmt_bin=$2

find src -name "*.hs" | while read -r f; do
if ! "${ormolu_bin}" -m 'check' "$f" 1> /dev/null 2> /dev/null ; then
  echo "$f is not formatted, aborting."
  exit 1
fi
done

if ! "${ormolu_bin}" -m 'check' "Setup.hs" 1> /dev/null 2> /dev/null ; then
  echo "Setup.hs is not formatted, aborting."
  exit 1
fi

find . -maxdepth 1 -name "*.cabal" | while read -r f; do
if ! "${cabal_fmt_bin}" -c "$f" ; then
  echo "$f is not formatted, aborting."
  exit 1
fi
done
