#!/usr/bin/bash

# Check if a double-quoted sentence argument is provided
if [[ $# -gt 0 && "$1" =~ ^\".*\"$ ]]; then
    # Double-quoted sentence argument found
    message="$1"
    echo "Detected message: $message"

    # Rest of your upload logic (e.g., git add, upload command)
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "Git repository detected, adding all changes..."
        git add .
        git commit -m "$message"
        git push
    else
        echo "Not a Git repository, skipping 'git add'."
    fi

else
    check
fi
