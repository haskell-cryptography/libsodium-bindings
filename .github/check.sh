#!/bin/sh

haskell_files=$(find src -name "*.hs")

if which "$1/ormolu" > /dev/null ; then
  for f in ${haskell_files}; do
    if ! "$1/ormolu" -m 'check' "$f" 1> /dev/null 2> /dev/null ; then 
      echo "$f is not formatted, aborting."
      exit 1
    fi
  done
  if ! "$1/ormolu" -m 'check' 'Setup.hs' 1> /dev/null 2> /dev/null ; then
    echo "Setup.hs is not formatted, aborting."
    exit 1
  fi
else
  echo "Ormolu not found, aborting."
  exit 1
fi

if which "$1/hlint" > /dev/null ; then
  for f in ${haskell_files}; do
    if ! "$1/hlint" -h '.hlint.yaml' -q "$f" ; then
      exit 1
    fi
  done
else
  echo "HLint not found, aborting."
  exit 1
fi

if which "$1/cabal-fmt" > /dev/null ; then
  if ! "$1/cabal-fmt" -c "cryptography-libsodium-bindings.cabal" ; then
    exit 1
  fi
else
  echo "cabal-fmt not found, aborting."
  exit 1
fi
