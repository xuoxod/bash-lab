#!/usr/bin/env bash
<<COMMENT
    Helper script
COMMENT

set -e          # Exit if any command has a non-zero exit status
set -u          # Set variables before using them
set -o pipefail # Prevent pipeline errors from being masked
set -m          # enable job control
# set -x Prints command to the console
source constants.sh
source patterns.sh
source ./actions.sh

ARG=""
MSG=""
SCRIPT=""
ARG_COUNT=0

clearVars() {
    unset ARG MSG SCRIPT ARG_COUNT
}

gracefulExit() {
    clearVars
    exit "$EXIT_PROG"
}

exitProg() {
    gracefulExit
}

programSynopsis() {
    printf " \nSynopsis:\t $0 <[OPTION]> [ARGUMENT]\n\n"
    printf "Usage:\t $0 - <[ps]> [argument]\n\n\n"
    printf "Options:\n\n"
    printf "\t-p:   Generate a random non-pronouncable string.\n"
    printf "\n\t          Example:\n"
    printf "\n\t               $0 -p off\n\n"
    exitProg
}

trap "gracefulExit" INT TERM QUIT PWR STOP KILL

pflag=
sflag=
start=
final=
optspec=":sp-"
while getopts "$optspec" OPTION; do
    case "${OPTION}" in
    p)
        ARGS=$@
        ARG_COUNT=$#
        SCRIPT=$0
        SWITCH=$1
        MSG="\n\n"
        pflag=1

        if [[ "$ARG_COUNT" -eq 1 ]]; then
            generateNonpronounceblePassword
        elif [[ "$ARG_COUNT" -eq 2 ]]; then
            ARG1=$2
            if [ "$ARG1" == "off" ]; then
                generatePronounceblePassword
            else
                generateNonpronounceblePassword
            fi
        fi
        ;;

    s)
        sflag=1
        randomStringGeneratorSynopsis
        ;;

    *)
        if [ "$OPTERR" != 1 ] || [ "${optspec:0:1}" = ":" ]; then
            printf "Illegal flag: '-${OPTARG}'\n\n" >&2
        fi
        ;;
    esac
done

# if [ ! -z "$pflag" ]; then

shift "$(($OPTIND - 1))"

if [[ "$#" -eq 1 ]]; then
    final="$# remaining argument\n"
    printf "#*"
elif [[ "$#" -eq 0 ]] || [[ "$#" -gt 1 ]]; then
    final="$# remaining arguments\n"
fi

if [[ "$#" -gt 1 ]]; then
    printf "$final"
    for A in $@; do
        printf "  $A\n"
    done
    usage
fi
