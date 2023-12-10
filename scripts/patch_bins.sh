#!/bin/bash
# Script that auto patches every binary in a directory

if [ $# -lt 3 ]; then
    echo "Usage: $0 <directory> <libc> <ld>"
    exit 1
fi

directory="$1"
libc="$2"
ld="$3"
if [ ! -d "$directory" ]; then
    echo "Directory not found: $directory"
    exit 1
fi

if [ ! -d "$libc" ]; then
    echo "No libc provided"
    exit 1
fi 

if [ ! -d "$ld" ]; then
    echo "No ld provided"
    exit 1
fi 

for file in "$directory"/*; do
    if [ -f "$file" ]; then
        pwninit --no-template --bin $file --libc "/home/solardebris/development/aegis/libc/libc.so.6" --ld "/home/solardebris/development/aegis/libc/ld-2.27.so"
        mv "${file}_patched" "$file"
    fi
done

