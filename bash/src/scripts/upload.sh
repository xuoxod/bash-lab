#!/usr/bin/bash

message="Minor update"

# Check if current dir is within a Git repository
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then

    # Check for changes
    if git diff-index --quiet HEAD --; then
        printf "No changes to commit. Releasing message: %s\n\n" "${message}"
        git status -v --long
    else
        # Get commit message from argument or default
        if [[ $# -gt 0 && "$1" =~ ^\".*\"$ ]]; then
            message="$1"
        fi

        # Prompt for confirmation
        read -r -p "Commit and push changes with message: '$message'? [y/N] " response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            git add .
            git commit -m "$message" && git push
            printf "\n\n"
            git status -v --long
            printf "\n\n"
        else
            echo "Aborting commit and push."
        fi
    fi

else
    echo "Not a Git repository, skipping git commands"
fi
