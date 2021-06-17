#!/bin/bash
#
# This script can help reviewing man pages in rpm packages during
# RHEL 7 Man Page Scan.
#
# Usage:  ./man-page-day.sh package-name
#
# This code is in the public domain; do with it what you wish.
#
# Copyright (C) 2012 Peter Schiffer <pschiffe@redhat.com>
#

# November 28, 2012
VERSION=0.2


# Global stat variables
stats_ok=0
stats_warn=0
stats_error=0

################################################################################
# Functions
################################################################################

# Print short usage information
function usage {
    msg "./man-page-day.sh <package-name>"
    msg "./man-page-day.sh -? | --help | --usage | -v | --version"
}

# Print help
function help_info {
    usage
    msg
    msg "man-page-day.sh script can help during the RHEL-7 man page scan to automate simple
tasks. It performs checks on man pages, prints warnings, etc. None of these
messages should be taken too seriously, user caution is advised.
Script takes one argument, a package name to be inspected.

The script can:
 * Install qa-tools package if needed (it also can add qa-tools.repo)
 * Install the inspected package if needed
 * Check whether binary files (in /(s)bin, /usr/(s)bin) have man pages
 * Check section of these man pages (should be 1 or 8)
 * Check whether config files (in /etc) have man pages
 * Check section of these man pages (should be 5)
 * Display all unassigned man pages
Since 0.2:
 * Check man pages with lexgrog
 * Check for double words in man pages
"
}

# Report error to the stderr and exit
# $1    error message to be printed
# $2    if given second parameter, do not exit, just print the message
function error {
    [[ $# -eq 1 || $# -eq 2 ]] || error "error() function requires 1 or 2 parameters"
    [[ -n "$1" ]] || error "error() function requires at least one parameter"

    echo "$1" >&2

    if [[ $# -eq 1 ]]; then
        exit 1
    fi
}

# Print message on stdout
# if no parameter given, print newline
# $1    message to be printed
# $2    optional    ok | warn | error   if given, prefix message with level
function msg {
    [[ $# -eq 0 || $# -eq 1 || $# -eq 2 ]] || error "msg() function requires 0, 1 or 2 parameters"

    if [[ $# -eq 0 ]]; then
        echo
        return 0
    fi

    if [[ $# -eq 1 ]]; then
        echo "$1"
        return 0
    fi

    [[ $2 == "ok" || $2 == "warn" || $2 == "error" ]] || \
        error "msg() function requires second parameter to be one of: 'ok', 'warn' or 'error'"

    txtbld=$(tput bold)             # Bold
    bldred=${txtbld}$(tput setaf 1) #  red
    bldgrn=${txtbld}$(tput setaf 2) #  green
    bldylw=${txtbld}$(tput setaf 3) #  yellow
    txtrst=$(tput sgr0)             # Reset

    format="%s %s\n"

    case "$2" in
        "ok")
            printf "$format" "[ ${bldgrn}OK${txtrst} ]" "$1"
            ((stats_ok++))
            ;;
        "warn")
            printf "$format" "[ ${bldylw}Warn${txtrst} ]" "$1"
            ((stats_warn++))
            ;;
        "error")
            printf "$format" "[ ${bldred}Error${txtrst} ]" "$1"
            ((stats_error++))
            ;;
    esac
}

# Get manpage for given file
# $1    file which should have man page
# $2    array   man pages in package
# return man page or 1 if none found
function get_manpage {
    [[ $# -ge 1 ]] || error "get_manpage() function requires at least 1 parameters"

    # No man pages given
    [[ $# -eq 1 ]] && return 2

    bin=$(basename "$1")
    binalt="${bin//./-}"
    shift

    while [[ $# -gt 0 ]]; do
        base=$(basename "$1")
        base="${base%\.[0-9]\.*}"
        if [[ "$bin" == "$base" || "$binalt" == "$base" ]]; then
            echo "$1"
            return 0
        fi
        shift
    done

    return 1
}

# Get section of the given man page
# $1    man page
# return section of man page
function get_section_of_manpage {
    [[ $# -eq 1 ]] || error "get_section_of_manpage() function requires 1 parameter"
    [[ -n $1 ]] || error "get_section_of_manpage() function requires 1 string parameter"

    section="${1%\.*}"
    section="${section##*\.}"

    echo "$section"
}

# Get position of item in given array
# $1    item
# $2    array
# return position
function get_position_of_item {
    [[ $# -ge 2 ]] || error "get_position_of_item() function requires at least 2 parameters"

    item="$1"
    shift

    i=0
    while [[ $# -gt 0 ]]; do
        if [[ "$item" == "$1" ]]; then
            echo $i
            return 0
        fi
        shift
        ((i++))
    done

    echo -1
}


################################################################################
# Main
################################################################################

# Check param
if [[ $# -ne 1 ]]; then
    error "package name is required as a parameter" "no-exit"
    help_info
    exit 1
fi

# Print help and usage if needed
if [[ $1 == "-?" || $1 == "--help" ]]; then
    help_info
    exit 0
elif [[ $1 == "--usage" ]]; then
    usage
    exit 0
elif [[ $1 == "-v" || $1 == "--version" ]]; then
    msg $VERSION
    exit 0
fi

package=$1

# Check for qa-tools package, try to install it if it's not
if ! $(rpm --quiet -q qa-tools); then
    if [[ ! -f /etc/yum.repos.d/qa-tools.repo ]]; then
        msg "setting up qa-tools.repo:"
        su -c "wget -O /etc/yum.repos.d/qa-tools.repo \
http://liver.englab.brq.redhat.com/repo/qa-tools.repo"
    fi
    msg "installing qa-tools package:"
    su -c "yum install qa-tools"
fi

# Install package if needed
if ! $(rpm --quiet -q $package); then
    msg "installing package ${package}:"
    su -c "yum install ${package}"
fi


# Get files
declare -a binfiles
declare -a conffiles
declare -a manfiles
declare -a manfilesleft     # "unused" man pages

msg "Current version of package:"
msg "$(rpm -q $package)"
for f in $(rpm -ql $package); do
    if [[ "${f}" == /usr/share/man/* ]]; then
        manfiles+=("${f}")
        continue
    fi
    if [[ "${f}" == /etc* ]]; then
        conffiles+=("${f}")
        continue
    fi
    if [[ "${f}" == /usr/bin* || "${f}" == /usr/sbin* \
            || "${f}" == /bin* || "${f}" == /sbin* ]]; then
        binfiles+=("${f}")
    fi
done

# Duplicate manfiles array, so we know, which man pages was "unused"
manfilesleft=("${manfiles[@]}")

# Check if bin files has man pages
msg
msg "checking whether binary files have man pages:"
msg
for f in "${binfiles[@]}"; do
    mp=$(get_manpage "$f" "${manfilesleft[@]}")
    if [[ ! "$mp" ]]; then
        msg "binary $f has no man page!" "error"
    else
        msg "binary $f has man page $mp" "ok"
        sec=$(get_section_of_manpage "$mp")
        if [[ "$sec" == "1" ]]; then
            msg "man page is in section 1" "ok"
        elif [[ "$sec" == "8" ]]; then
            msg "man page is in section 8. Only commands requiring admin privileges, \
or deamons should be in this section, the rest should be in section 1" "warn"
        else
            msg "man page is in unexpected section ${sec}. Man pages for binaries should \
be in section 1, or if binary requires admin privileges or if binary is a deamon, then \
the man page should be in section 8" "error"
        fi
        # Remove "used" man page
        pos=$(get_position_of_item "$mp" "${manfilesleft[@]}")
        manfilesleft=(${manfilesleft[@]:0:$pos} ${manfilesleft[@]:$(($pos + 1))})
    fi
done

# Check if config files has man pages
msg
msg "checking whether config files have man pages:"
msg
for f in "${conffiles[@]}"; do
    [[ -d "$f" ]] && continue
    mp=$(get_manpage "$f" "${manfilesleft[@]}")
    if [[ ! "$mp" ]]; then
        msg "config file $f has no man page! Check it's content for proper documentation" "error"
    else
        msg "config file $f has man page $mp" "ok"
        sec=$(get_section_of_manpage "$mp")
        if [[ "$sec" == "5" ]]; then
            msg "man page is in section 5" "ok"
        else
            msg "man page is in unexpected section ${sec}. Man pages for configuration \
files should be in section 5" "error"
        fi
        # Remove "used" man page
        pos=$(get_position_of_item "$mp" "${manfilesleft[@]}")
        manfilesleft=(${manfilesleft[@]:0:$pos} ${manfilesleft[@]:$(($pos + 1))})
    fi
done

# Check whether we used all man pages
msg
msg "checking for unused man pages:"
msg
if [[ ${#manfilesleft[@]} -eq 0 ]]; then
    msg "no man pages left" "ok"
else
    msg "these (${#manfilesleft[@]}) man pages left unassigned:" "warn"
    for m in "${manfilesleft[@]}"; do
        msg "$m"
    done
fi

# Now check individual man pages
msg
msg "now checking individual man pages:"
msg
tmpdir=$(mktemp -d)
for m in "${manfiles[@]}"; do
    msg "checking ${m}:"

    # Skip symbolic links
    if [[ -L "$m" ]]; then
        target=$(readlink -f "$m")
        msg "this man page is link to ${target}, skipping"
        msg
        continue
    fi

    # Extract man page
    ml=$(basename "$m")
    ml="${tmpdir}/${ml%\.*}"
    gunzip -c "$m" > "$ml"

    # Skip .so links
    headline=$(head -n 1 "$ml")
    if [[ "$headline" == .so* ]]; then
        target=$(echo "/usr/share/man/${headline:4}"*)
        msg "this man page is link to ${target}, skipping"
        msg
        rm "$ml"
        continue
    fi

    # Run lexgrog
    if $(lexgrog "$ml" > /dev/null); then
        msg "man page parsing with lexgrog succeeded" "ok"
    else
        msg "man page parsing with lexgrog failed. See lexgrog(1) for more info" "error"
    fi

    # Check for repeated words
    words=$(MANWIDTH=2000 man -l "$ml" 2> /dev/null | col -b | \
    tr ' \008' '\012' | sed -e '/^$/d' | \
    sed 's/ *$//' | 
    awk 'BEGIN {p=""} {if (p==$0) print p; p=$0}' | \
    grep '[a-zA-Z]' | tr '\012' ' ')
    if [[ -n "$words" ]]; then
        msg "found repeated words in man page: ${words}" "warn"
    else
        msg "man page doesn't contain any repeated word" "ok"
    fi

    rm "$ml"
    msg
done
rmdir $tmpdir


msg "Summary: ${stats_ok}x OK, $stats_warn warnings, $stats_error errors"
exit 0


