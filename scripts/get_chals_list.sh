#!/bin/bash

export CTFD_TOK=$(cat ~/ctfd_tok)

#ctfd="https://ace.ctfd.io"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <ctfd>"
    exit 1
fi


ctfd=$1
api_endpoint="/api/v1/challenges"
challenge_url="${ctfd}${api_endpoint}"

json_response=$(curl -s -H "Authorization: Token $CTFD_TOK" -H "Content-Type: application/json" "$challenge_url")

csv_data=$(echo "$json_response" | jq -r '.data[] | [.name, .id, .category] | @csv')
chals="../bininfo/challenges.csv"
echo "$csv_data" | grep "pwn" | sed "s/\"//g" | sed "s/\,/\ /g" | awk '{print "ace-service-" $1 ".chals.io " "bins/" $1 " "$2}' | sort > "$chals"

