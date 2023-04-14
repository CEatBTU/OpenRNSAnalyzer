#!/bin/bash

readelf -r "$1" | \
    awk '/[0-9a-f]+\s*[0-9a-f]+\s*R_PPC64_RELATIVE\s*[0-9a-f]+$/ { print $1, $4 }' \
        > "$2"
