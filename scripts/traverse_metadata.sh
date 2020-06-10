#!/bin/bash

# Description:
# This script is used to get all the metadata in cloud instance.
#
# History:
# v1.0     2018-08-28  charles.shih  Initial version
# v1.1     2019-01-16  charles.shih  Support running on Azure
# v1.2     2019-02-26  charles.shih  Support running on AWS
# v1.2.1   2019-02-26  charles.shih  Move function and update comments
# v1.3     2019-03-21  charles.shih  Support running on Huawei
# v1.4     2019-11-27  charles.shih  Support running on Alibaba EBM

debug() { [ ! -z $DEBUG ] && echo "DEBUGINFO: $@"; }

die() { echo "ERROR: Line $@"; exit 1; }


determine_cloud_provider() {
	# Description: Try to determine the cloud provider
	# Update:
	#   - $cloud:
	#     Possible Values: aws/azure/alibaba/other
	# Return: 0 - success / 1 - failed

	debug "Enter func determine_cloud_provider"

	# AWS
	dmesg | grep -q " DMI: Amazon EC2" && cloud=aws && return 0
	dmesg | grep -q " DMI: Xen HVM domU" && cloud=aws && return 0

	# Azure
	dmesg | grep -q " DMI: Microsoft Corporation Virtual Machine" && cloud=azure && return 0

	# Alibaba
	dmesg | grep -q " DMI: Alibaba Cloud" && cloud=alibaba && return 0		# Non-EBM
	dmesg | grep -q " DMI: Alibaba Alibaba Cloud" && cloud=alibaba && return 0	# EBM

	# Huawei (to be done in a better way)
	dmesg | grep -q " DMI: OpenStack Foundation OpenStack" && cloud=huawei && return 0

	# To be supported
	cloud=other
	return 1
}


determine_baseurl() {
	# Description: Try to determine the baseurl
	# Update: $baseurl
	# Return: 0 - success / 1 - failed

	debug "Enter func determine_baseurl"

	determine_cloud_provider

	case $cloud in
		aws)
			baseurl="http://169.254.169.254/latest/meta-data/"
			;;
		azure)
			baseurl="http://169.254.169.254/metadata/"
			;;
		alibaba)
			baseurl="http://100.100.100.200/latest/meta-data/"
			;;
		huawei)
			baseurl="http://169.254.169.254/2009-04-04/meta-data/"
			;;
		other)
			return 1
			;;
	esac

	return 0
}


traverse() {
	# Description: Traverse the metadata (recursive algorithm)
	# Inputs:
	#   - The metadata URL
	# Varibles:
	#   - $cloud
	# Outputs:
	#   - the metadata contents

	debug "Enter func traverse, args = $@"

	display() {
		# Description: Display the metadata content
		# Inputs:
		#   - $1: URL for metadata to display
		# Dependence:
		#   - $cloud
		#   - die()
		# Display:
		#   - the URL and its content
		# Outputs:
		#   n/a
		# Return:
		#   n/a

		debug "Enter func display, args = $@"

		echo $1

		if [ $cloud != azure ]; then
			x=$(curl --connect-timeout 10 $1 2>/dev/null)
		else
			# For Azure
			x=$(curl --connect-timeout 10 -H Metadata:true ${1}?api-version=2019-03-11\&format=text 2>/dev/null)
		fi

		[ $? != 0 ] && die "$LINENO: curl failed with code=$?."
		[[ ! "$x" =~ "404 - Not Found" ]] && echo "$x" || echo "404 - Not Found"

		return
	}


	local root=$1

	if [ $cloud != azure ]; then
		x=$(curl --connect-timeout 10 $root 2>/dev/null)
	else
		# For Azure
		x=$(curl --connect-timeout 10 -H Metadata:true ${root}?api-version=2019-03-11\&format=text 2>/dev/null)
	fi

	[ $? != 0 ] && die "$LINENO: curl failed with code=$?."
	[[ "$x" =~ "404 - Not Found" ]] && die "$LINENO: Err 404 - Not Found."

	debug "root = $root; x = $x"

	for child in $x; do
		#local child=$node

		# Deal with public-keys, example: "0=cheshi" -> "0/"
		[[ $root = *public-keys* ]] && [[ $child = *=* ]] && child="${child%%=*}/"

		if [[ $child = */ ]]; then
			# Non-leaf, continue traverse
			traverse ${root}${child}
		else
			# Leaf, display metadata content
			display ${root}${child}
		fi
	done
}


# Main
#DEBUG=yes
determine_baseurl || die "$LINENO: Unable to determine baseurl."
traverse $baseurl

exit 0

