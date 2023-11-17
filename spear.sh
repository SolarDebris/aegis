#!/bin/bash

ctfd="https://ace.ctfd.io"

api_endpoint="/api/v1/challenges"
challenge_url="${ctfd}${api_endpoint}"

json_response=$(curl -s -H "Authorization: Token $CTFD_TOK" -H "Content-Type: application/json" "$challenge_url")

csv_data=$(echo "$json_response" | jq -r '.data[] | [.name, .id] | @csv')

echo "$csv_data" | sed "s/\"//g" | sed "s/\,/\ /g" | awk '{print " ace-service-" $1 ".chals.io " "bins/" $1 " "$2}'  > challenges.csv

chals="./challenges.csv"

if [ ! -f "$chals" ]; then
  echo "File not found: $chals"
  exit 1
fi


MAX_PROCESSES=10

active_processes=0

track_processes() {
    active_processes=$(jobs -p | wc -l)
}

# Read each line from the file
while IFS= read -r line; do
    read -r service file_path id <<< "$line"
  
    command1="pwninit --libc libc/libc.so.6 --ld libc/ld-2.27.so --bin $file_path"
    patched_file=$file_path"_patched"
    echo "$patched_file"
    command2="mv $patched_file $file_path"

    command="./aegis -bin $file_path -ip $service -ctfd $ctfd -id $id"
    

    #while [ $active_processes -ge $MAX_PROCESSES ]; do
        #track_processes
        #hsleep 1
    #done

    #((active_processes++))
    #echo "$command"
    #{
    echo "$command1" | sh
    echo "$command2" | sh
    echo "$command"
    echo "$command" | sh
        #((active_processes--))
    #} &
done < "$chals"

#echo $command | sh 
#./aegis -bin bins/test-binaries/bin-write_gadgets-1 -ip ace-service-bin-write-gadgets-1.chals.io -ctfd https://ace.ctfd.io -id 126

