#!/bin/bash

# Description:
# This script is used to get general information in Linux OS by running varity of
# Linux commands. Some of them require super user permission, so this script should be
# running by root.
#
# History:
# v1.0     2018-06-26  charles.shih  Initial version
# v1.1     2018-07-10  charles.shih  Add commands for cloud-init and others
# v1.2     2018-07-12  charles.shih  Add commands lspci
# v1.3     2018-07-13  charles.shih  Remove command cat /proc/kmsg
# v2.0     2018-07-13  charles.shih  Support running on Non-AWS
# v2.1     2018-07-16  charles.shih  Remove command cat /proc/kpage*
# v2.2     2018-07-16  charles.shih  Add some commands for network and cloud-init
# v2.3     2018-07-20  charles.shih  Add some commands for network
# v2.4     2018-07-20  charles.shih  Add some command journalctl to get system log
# v2.5     2018-08-15  charles.shih  Add message to show where the log is saved to
# v2.6     2018-08-15  charles.shih  Add /usr/local/sbin:/usr/sbin into PATH
# v2.7     2018-08-15  charles.shih  Install package redhat-lsb
# v2.8     2018-08-28  charles.shih  Auto add sudo before commands
# v2.9     2018-08-28  charles.shih  Save error outputs into *.log.err
# v2.10    2018-08-28  charles.shih  Display error messages when command failure
# v2.11    2018-08-28  charles.shih  Modify some commands and do some enhancement
# v2.11.1  2018-09-10  charles.shih  Fix a typo in command
# v2.12    2018-11-27  charles.shih  Add some commands for yum and subscription
# v2.13    2019-01-16  charles.shih  Support running on Azure instance
# v2.14    2019-01-16  charles.shih  Support running on Aliyun instance
# v2.15    2019-01-21  charles.shih  Get target output path from parameter
# v2.16    2019-02-15  charles.shih  Remove command cat /proc/kallsyms
# v2.17    2019-04-15  charles.shih  Add some commands for SELinux
# v2.17.1  2019-07-05  charles.shih  Adjust the commands order
# v2.17.2  2019-07-06  charles.shih  Fix a minor problem
# v2.18    2019-08-20  charles.shih  Add vulnerablilities files check
# v2.18.1  2019-09-20  charles.shih  Bugfix for vulnerablilities files check
# v2.19    2019-10-10  charles.shih  Add vulnerablilities files check command
# v2.20    2020-03-03  charles.shih  Add dmidecode command
# v2.21    2020-05-21  charles.shih  Add command 'systemctl status'
# v2.22    2020-05-28  charles.shih  Add some commands for cloud-init
# v2.23    2020-06-01  charles.shih  Update commands for cloud-init
# v2.23.1  2020-07-30  charles.shih  Bugfix on cloud-init command
# v2.24    2020-07-30  charles.shih  Add commands for memory
# v2.25    2020-08-19  charles.shih  Add commands for other Linux distros
# v2.26    2020-09-23  charles.shih  Add sysctl command
# v2.27    2021-07-01  charles.shih  Add EFI check command
# v2.28    2021-07-01  charles.shih  Add Aliyun image-id check command

# Notes:
# On AWS the default user is ec2-user and it is an sudoer without needing a password;
# On Azure and Aliyun the default user is root.

show_inst_type() {

	# AWS
	dmesg | grep -q " DMI: Amazon EC2"
	if [ $? = 0 ]; then
		curl http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null
		return 0
	fi

	# Azure
	dmesg | grep -q " DMI: Microsoft Corporation Virtual Machine"
	if [ $? = 0 ]; then
		curl -H Metadata:true http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2017-04-02\&format=text
		return 0
	fi

	# Aliyun
	dmesg | grep -q " DMI: Alibaba Cloud"
	if [ $? = 0 ]; then
		curl http://100.100.100.200/latest/meta-data/instance/instance-type 2>/dev/null
		return 0
	fi

	# To be supported
	return 1
}

function run_cmd(){
	# $1: Command to be executed
	# $2: The filename where log to be saved (optional)

	# If not root, lead the command with 'sudo'
	[ $(whoami) = root ] && cmd="$1" || cmd="sudo $1"

	if [ -z "$2" ]; then
		cmdlog=$base/$(echo $cmd | tr -c "[:alpha:][:digit:]" "_").log
	else
		cmdlog=$base/$2
	fi

	echo -e "\ncmd> $cmd" >> $joblog
	echo -e "log> $cmdlog[.err]" >> $joblog
	eval $cmd > $cmdlog 2> $cmdlog.err
	
	rcode=$?
	if [ $rcode != 0 ]; then
		echo -e "\ncmd> $cmd"
		cat $cmdlog.err
    fi

    return $rcode
}

export PATH=$PATH:/usr/local/sbin:/usr/sbin

# Prepare environment
if [ -z "$1" ]; then
	inst_type=$(show_inst_type)
	time_stamp=$(date +%Y%m%d%H%M%S)
	base="$HOME/workspace/log/vm_check_${inst_type:=unknown}_${time_stamp:=random$$}"
else
	base="$1"
fi

mkdir -p $base
joblog=$base/job.txt


echo -e "\n\nInstallation:\n===============\n" >> $joblog

# Install essential tools
sudo yum install sysstat -y &>> $joblog
sudo yum install redhat-lsb -y &>> $joblog

echo -e "\n\nTest Results:\n===============\n" >> $joblog

# Start VM check

## virtualization
run_cmd 'virt-what'

## system
run_cmd 'cat /proc/version'
run_cmd 'uname -r'
run_cmd 'uname -a'
run_cmd 'lsb_release -a'
run_cmd 'cat /etc/redhat-release'
run_cmd 'cat /etc/issue'
run_cmd 'cat /etc/lsb-release'
run_cmd 'cat /etc/os-release'

## bios and hardware
run_cmd 'dmidecode'
run_cmd 'dmidecode -t bios'
run_cmd 'lspci'
run_cmd 'lspci -v'
run_cmd 'lspci -vv'
run_cmd 'lspci -vvv'
run_cmd 'ls -d /sys/firmware/efi'

## package
run_cmd 'rpm -qa'
run_cmd 'yum repolist'
run_cmd 'yum repolist all'
run_cmd 'yum repoinfo'
run_cmd 'yum repoinfo all'
run_cmd 'subscription-manager list --available'
run_cmd 'subscription-manager list --consumed'
run_cmd 'grep ^ /etc/yum.repos.d/*'

## kernel
run_cmd 'lsmod'
run_cmd 'date'
run_cmd 'cat /proc/uptime'
run_cmd 'uptime'
run_cmd 'top -b -n 1'
run_cmd 'bash -c set'
run_cmd 'env'
run_cmd 'vmstat 3 1'
run_cmd 'vmstat -m'
run_cmd 'vmstat -a'
run_cmd 'w'
run_cmd 'who'
run_cmd 'whoami'
run_cmd 'ps -A'
run_cmd 'ps -Al'
run_cmd 'ps -AlF'
run_cmd 'ps -AlFH'
run_cmd 'ps -AlLm'
run_cmd 'ps -ax'
run_cmd 'ps -axu'
run_cmd 'ps -ejH'
run_cmd 'ps -axjf'
run_cmd 'ps -eo euser,ruser,suser,fuser,f,comm,label'
run_cmd 'ps -axZ'
run_cmd 'ps -eM'
run_cmd 'ps -eo pid,tid,class,rtprio,ni,pri,psr,pcpu,stat,wchan:14,comm'
run_cmd 'ps -axo stat,euid,ruid,tty,tpgid,sess,pgrp,ppid,pid,pcpu,comm'
run_cmd 'ps -eo pid,tt,user,fname,tmout,f,wchan'
run_cmd 'free'
run_cmd 'free -k'
run_cmd 'free -m'
run_cmd 'free -g'
run_cmd 'free -h'
run_cmd 'cat /proc/meminfo'
run_cmd 'lscpu'
run_cmd 'cat /proc/cpuinfo'
run_cmd 'mpstat -P ALL'
run_cmd 'sar -n DEV'
run_cmd 'iostat'
run_cmd 'netstat -tulpn'
run_cmd 'netstat -nat'
run_cmd 'ss -t -a'
run_cmd 'ss -u -a'
run_cmd 'ss -t -a -Z'
run_cmd 'cat /proc/zoneinfo'
run_cmd 'cat /proc/mounts'
run_cmd 'cat /proc/interrupts'
run_cmd 'dmesg'
run_cmd 'dmesg -l emerg'
run_cmd 'dmesg -l alert'
run_cmd 'dmesg -l crit'
run_cmd 'dmesg -l err'
run_cmd 'dmesg -l warn'
run_cmd 'dmesg -l notice'
run_cmd 'dmesg -l info'
run_cmd 'dmesg -l debug'
run_cmd 'dmesg -f kern'
run_cmd 'dmesg -f user'
run_cmd 'dmesg -f mail'
run_cmd 'dmesg -f daemon'
run_cmd 'dmesg -f auth'
run_cmd 'dmesg -f syslog'
run_cmd 'dmesg -f lpr'
run_cmd 'dmesg -f news'
run_cmd 'sysctl -a'

## block
run_cmd 'lsblk'
run_cmd 'lsblk -p'
run_cmd 'lsblk -d'
run_cmd 'lsblk -d -p'
run_cmd 'df -k'
run_cmd 'fdisk -l'

## network
run_cmd 'ifconfig -a'
run_cmd 'ethtool eth0'
run_cmd 'ethtool -a eth0'
run_cmd 'ethtool -i eth0'
run_cmd 'ethtool -c eth0'
run_cmd 'ethtool -g eth0'
run_cmd 'ethtool -k eth0'
run_cmd 'ethtool -n eth0'
run_cmd 'ethtool -T eth0'
run_cmd 'ethtool -x eth0'
run_cmd 'ethtool -P eth0'
run_cmd 'ethtool -l eth0'
run_cmd 'ethtool -S eth0'
run_cmd 'ethtool --phy-statistics eth0'
run_cmd 'ethtool --show-priv-flags eth0'
run_cmd 'ethtool --show-eee eth0'
run_cmd 'ethtool --show-fec eth0'
run_cmd 'ip link'
run_cmd 'ip address'
run_cmd 'ip addrlabel'
run_cmd 'ip route'
run_cmd 'ip rule'
run_cmd 'ip neigh'
run_cmd 'ip ntable'
run_cmd 'ip tunnel'
run_cmd 'ip tuntap'
run_cmd 'ip maddress'
run_cmd 'ip mroute'
run_cmd 'ip mrule'
run_cmd 'ip netns'
run_cmd 'ip l2tp show tunnel'
run_cmd 'ip l2tp show session'
run_cmd 'ip macsec show'
run_cmd 'ip tcp_metrics'
run_cmd 'ip token'
run_cmd 'ip netconf'
run_cmd 'ip ila list'
run_cmd 'hostname'
run_cmd 'cat /etc/hostname'
run_cmd 'cat /etc/hosts'
run_cmd 'ping -c 1 8.8.8.8'
run_cmd 'ping6 -c 1 2001:4860:4860::8888'

## cloud-init
run_cmd 'cat /var/log/cloud-init.log'
run_cmd 'cat /var/log/cloud-init-output.log'
run_cmd 'service cloud-init-local status'
run_cmd 'service cloud-init status'
run_cmd 'service cloud-config status'
run_cmd 'service cloud-final status'
run_cmd 'systemctl status cloud-{init-local,init,config,final}'
run_cmd 'cloud-init status'
run_cmd 'cloud-init analyze show'
run_cmd 'cloud-init analyze blame'
run_cmd 'cloud-init analyze dump'
run_cmd 'cat /var/run/cloud-init/status.json'
run_cmd 'cat /var/run/cloud-init/instance-data.json'
run_cmd 'cat /var/run/cloud-init/ds-identify.log'
run_cmd 'cat /etc/cloud/cloud.cfg'
run_cmd 'cat /run/cloud-init/cloud-init-generator.log'
run_cmd 'cat /run/cloud-init/ds-identify.log'
run_cmd 'cloud-id'

## selinux
run_cmd 'getenforce'

## others
run_cmd 'cat /proc/buddyinfo'
run_cmd 'cat /proc/cgroups'
run_cmd 'cat /proc/cmdline'
run_cmd 'cat /proc/consoles'
run_cmd 'cat /proc/crypto'
run_cmd 'cat /proc/devices'
run_cmd 'cat /proc/diskstats'
run_cmd 'cat /proc/dma'
run_cmd 'cat /proc/execdomains'
run_cmd 'cat /proc/fb'
run_cmd 'cat /proc/filesystems'
run_cmd 'cat /proc/iomem'
run_cmd 'cat /proc/ioports'
run_cmd 'cat /proc/keys'
run_cmd 'cat /proc/key-users'
run_cmd 'cat /proc/loadavg'
run_cmd 'cat /proc/locks'
run_cmd 'cat /proc/mdstat'
run_cmd 'cat /proc/misc'
run_cmd 'cat /proc/modules'
run_cmd 'cat /proc/mtrr'
run_cmd 'cat /proc/pagetypeinfo'
run_cmd 'cat /proc/partitions'
run_cmd 'cat /proc/sched_debug'
run_cmd 'cat /proc/schedstat'
run_cmd 'cat /proc/slabinfo'
run_cmd 'cat /proc/softirqs'
run_cmd 'cat /proc/stat'
run_cmd 'cat /proc/swaps'
run_cmd 'cat /proc/sysrq-trigger'
run_cmd 'cat /proc/timer_list'
run_cmd 'cat /proc/timer_stats'
run_cmd 'cat /proc/vmallocinfo'
run_cmd 'cat /proc/vmstat'

# Vulnerablilities files check
run_cmd 'ls /sys/devices/system/cpu/vulnerabilities/'
for file in $(ls /sys/devices/system/cpu/vulnerabilities/*); do
	run_cmd "grep ^ $file"
done

## specified collection
# Aliyun RHEL image
run_cmd 'cat /etc/image-id'

## boot
# Waiting for Bootup finished
while [[ "$(sudo systemd-analyze time 2>&1)" =~ "Bootup is not yet finished" ]]; do
	echo "[$(date)] Bootup is not yet finished." >> $joblog
	sleep 2s
done
run_cmd 'systemd-analyze time'
run_cmd 'systemd-analyze blame'
run_cmd 'systemd-analyze critical-chain'
run_cmd 'systemd-analyze dot'
run_cmd 'systemctl'
run_cmd 'systemctl status'
run_cmd 'cat /var/log/messages'
run_cmd 'journalctl'

# Finish
echo -e "\nLog files have been generated in \"$base\";"
echo -e "More details can be found in \"$joblog\"."

exit 0
