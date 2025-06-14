#!/bin/bash
FOLDER=$1
HOST=$2

show_help() {
    echo "Usage: PASSWORD=yourpassword $0 <folder> <host>"
    echo
    echo "Watches a folder and syncs it to a remote host on change."
    echo
    echo "Positional arguments:"
    echo "  <folder>            Folder to watch and sync"
    echo "  <host>              The host to connect to from ~/.ssh/config"
    echo
    echo "Optional environment variables:"
    echo "  PASSWORD            If set, uses sshpass for password-based SSH auth"
    exit 1
}

if [[ -z "$FOLDER" || "$FOLDER" == "-h" || "$FOLDER" == "--help" ]]; then
    show_help
fi

if [[ -n "$PASSWORD" ]]; then
    while inotifywait -r "$FOLDER"/*; do
        sshpass -p "$PASSWORD" rsync -ravz "$FOLDER" "$HOST" --delete:
    done
else
    while inotifywait -r "$FOLDER"/*; do
        rsync -ravz "$FOLDER" "$HOST" --delete:
    done
fi