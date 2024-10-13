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
source colors.sh

#  App's constants
declare -r EXIT_APP=0
declare -r ROOT_USER_ID=0
declare -r NON_ROOT_USER=1

EXIT_CODE=0
UNKNOWN_ERROR=121
ARGUMENT_ERROR=123
INTERNAL_ERROR=125
VERBOSITY=0

# Command string
command=""

# Script's variables
ARG=""
MSG=""
SCRIPT=""
ARG_COUNT=0
OPTION_SPEC="fqstp-"
TARGET_HOST=""
TARGET_PORT=""
USER_NAME=
PAUSE_TIME=2
SLEEP_TIME=5
CLEANING_TIME=3

# Options specification description
# -f:     Flushes DNS cache on current host
# -q:     Queries target host: Defaults to current host if target IP is not given
# -s:     Display DNS statistics on current target host
# -t:     Capture traffic to or from target host's ports
#           Examples:
#               sudo tcpdump -n host 10.212.33.201 and port 80 or port 30778 or port 53 -w host-packet-dump.pcap
#               sudo tcpdump -n host 192.168.1.158 and port 80 or port 30778 or port 53

clearVars() {
    unset ARG MSG SCRIPT ARG_COUNT TARGET_HOST TARGET_PORT
}

gracefulExit() {
    clearVars
    exit "$EXIT_CODE"
}

exitProg() {
    gracefulExit
}

exitUnknownError() {
    clearVars
    exit "$UNKNOWN_ERROR"
}

exitArgumentError() {
    clearVars
    exit "$ARGUMENT_ERROR"
}

exitInternalError() {
    clearVars
    exit "$INTERNAL_ERROR"
}

programSynopsis() {
    printf " \nSynopsis:  $0 <[OPTION]> [ARGUMENT]\n\n"
    printf "Usage:\t $0 - <[ps]> [argument]\n\n\n"
    printf "Options:\n\n"
    printf "\t-p:   Generate a random non-pronouncable string.\n"
    printf "\n\t          Example:\n"
    printf "\n\t               $0 -p off\n\n"
    exitProg
}

flushDns() {
    printf "\n\tArgument Count:  $ARG_COUNT\n\n"

    if [[ "$ARG_COUNT" -eq 1 ]]; then
        printf "$(figlet -cptW 'Flushing DNS Cache ...')\n\n"
    fi
}

start() {
    MSG="Initializing script ..."
    clear
    printf "\e[1;0;96m$(figlet -cptW $MSG)\n\e[0m"
    sleep "$PAUSE_TIME"
}

trap "gracefulExit" INT TERM QUIT PWR STOP KILL

# start

while getopts "$OPTION_SPEC" OPTION; do
    case "${OPTION}" in
    f)
        ARG_COUNT=$#
        SCRIPT=$0
        MSG="\n\n"
        flushDns
        ;;

    h)
        programSynopsis
        ;;

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

    q)
        ARG_COUNT=$#
        SCRIPT=$0
        MSG="\n\n"

        printf "\n\tArgument Count:  $ARG_COUNT\n\n"

        if [[ "$ARG_COUNT" -eq 1 ]]; then
            printf "$(figlet -cptW 'Querying DNS Cache ...')\n\n"
        elif [[ "$ARG_COUNT" -eq 2 ]]; then
            ARG="$2"
            printf "Assuming that $ARG is an IP address or a hostname\n\n"
            printf "$(figlet -cptW 'Querying DNS Cache ...')\n\n"
        fi
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
