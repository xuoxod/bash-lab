#!/usr/bin/bash

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    clear
    pwd
    printf "\n"
    ls
    printf "\n\n"
    git status
    printf "\n\n"
else
    echo "Not a Git repository, skipping 'git status check'."
fi
