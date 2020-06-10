#!/bin/bash

PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH

function show(){
	# $1: Title;
	# $@: Command;

	if [ "$1" = "" ]; then
		echo -e "\n\$$@"
	else
		echo -e "\n* $1"
	fi
	echo -e "---------------"; shift
	$@ 2>&1
}


show "Time" date

if [ "$(os_type.sh)" = "redhat" ]; then
	show "Release" cat /etc/system-release
else
	show "Release" cat /etc/issue
fi

show "" uname -a
show "" cat /proc/cmdline
show "" systemd-analyze

show "" cat /proc/cpuinfo
show "" cat /proc/meminfo
show "" lsblk -p
show "" ip addr
show "Metadata" metadata.sh

exit 0

