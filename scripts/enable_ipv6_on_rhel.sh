#!/bin/bash

# Description:
# 	This script is used to enable ipv6 on eth0 on RHEL system.
#
# Notes:
# 	If you launched your instance using Amazon Linux 2016.09.0 or later, or Windows Server 2008 R2 or later,
# 	your instance is configured for IPv6, and no additional steps are needed to ensure that the IPv6 address
# 	is recognized on the instance. If you launched your instance from an older AMI, you may have to configure
# 	your instance manually.
#
# Reference:
# 	http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-migrate-ipv6.html#ipv6-dhcpv6-rhel
#
#
# Before running this script on RHEL7.4:
#
# [ec2-user@ip-10-0-10-248 ~]$ ifconfig eth0
# eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
#        inet 10.0.10.248  netmask 255.255.255.0  broadcast 10.0.10.255
#        inet6 fe80::42f:5ff:fe3a:6336  prefixlen 64  scopeid 0x20<link>
#        ether 06:2f:05:3a:63:36  txqueuelen 1000  (Ethernet)
#        RX packets 1088  bytes 92455 (90.2 KiB)
#        RX errors 0  dropped 0  overruns 0  frame 0
#        TX packets 784  bytes 115690 (112.9 KiB)
#        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
#
# After running this script on RHEL7.4:
#
# [ec2-user@ip-10-0-10-248 ~]$ ifconfig eth0
# eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
#        inet 10.0.10.248  netmask 255.255.255.0  broadcast 10.0.10.255
#        inet6 fe80::42f:5ff:fe3a:6336  prefixlen 64  scopeid 0x20<link>
#        inet6 2406:da14:e7b:9b10:877d:ea41:15e9:e8d3  prefixlen 64  scopeid 0x0<global>
#        inet6 2406:da14:e7b:9b10:488:7498:3837:f1f1  prefixlen 64  scopeid 0x0<global>
#        ether 06:2f:05:3a:63:36  txqueuelen 1000  (Ethernet)
#        RX packets 1088  bytes 92455 (90.2 KiB)
#        RX errors 0  dropped 0  overruns 0  frame 0
#        TX packets 784  bytes 115690 (112.9 KiB)
#        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH


# Modify /etc/sysconfig/network-scripts/ifcfg-eth0

origfile="/etc/sysconfig/network-scripts/ifcfg-eth0"
tempfile=$(mktemp)

cat $origfile | grep -v "IPV6INIT=" | grep -v "DHCPV6C=" | grep -v "NM_CONTROLLED=" >> $tempfile
echo -e "IPV6INIT=yes\nDHCPV6C=yes\nNM_CONTROLLED=no" >> $tempfile

echo ""
echo "Modify $origfile"
echo "--------------------"
cat $origfile
echo "vvvvvvvvvvvvvvvvvvvv"
cat $tempfile
echo "--------------------"
echo ""

sudo sh -c "cat $tempfile > $origfile" && rm $tempfile

# Modify /etc/sysconfig/network

origfile="/etc/sysconfig/network"
tempfile=$(mktemp)

cat $origfile | grep -v "NETWORKING_IPV6=" >> $tempfile
echo -e "NETWORKING_IPV6=yes" >> $tempfile

echo ""
echo "Modify $origfile"
echo "--------------------"
cat $origfile
echo "vvvvvvvvvvvvvvvvvvvv"
cat $tempfile
echo "--------------------"
echo ""

sudo sh -c "cat $tempfile > $origfile" && rm $tempfile

echo "sudo service network restart"
sudo service network restart
echo ""

exit 0
