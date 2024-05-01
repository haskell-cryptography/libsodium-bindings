#!/usr/bin/env bash

case "$(uname -s)" in
        Linux*) sudo apt install libsodium-dev;;
        Darwin*) brew install libsodium;;
esac

