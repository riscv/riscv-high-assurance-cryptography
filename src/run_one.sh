#!/bin/sh
cd "$(dirname "$0")"
python3 "$1" > "$2" 2>&1
echo "exit=$?"
