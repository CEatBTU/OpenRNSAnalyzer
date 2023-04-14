#!/usr/bin/env zsh

source env.sh || true

git clone https://github.com/embench/embench-iot
ln -s embench-iot/src embench-src
ln -s embench-iot/support embench-support

cargo build
cargo build --release
./gen-all-stuff.py >| all-stuff.ninja
ninja -k0

./gen-index.py
