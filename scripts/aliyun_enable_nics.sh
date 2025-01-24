#!/bin/bash
PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH
count=$1

systemctl status NetworkManager
if [ $? = 0 ]; then
	echo "NetworkManager Enabled, the NICs should come up automatically."
	exit 0
fi

primary_nic=$(ifconfig | grep "flags=.*\<UP\>" | cut -d: -f1 |
	grep -e eth -e ens | head -n 1)
device_name=$(echo $primary_nic | tr -d '[:digit:]')
device_numb=$(echo $primary_nic | tr -d '[:alpha:]')

if [ "${device_name}" = "ens" ]; then
	echo "The ens* will come up automatically."
	exit 0
fi

# eth* ifup
spath="/etc/sysconfig/network-scripts"
for offset in $(seq 1 $count); do
	device=${device_name}$(($device_numb + $offset))
	cfgfile=$spath/ifcfg-${device}
	echo "STEP1: Create configure file ifcfg-${device}..."
	echo DEVICE=${device} >$cfgfile
	echo BOOTPROTO=dhcp >>$cfgfile
	echo ONBOOT=yes >>$cfgfile
	echo DEFROUTE=no >>$cfgfile
	cat $cfgfile
	echo "STEP2: 'ifup' this device..."
	sudo ifup ${device}
	sleep 1s
done

exit 0
