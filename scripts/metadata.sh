#!/bin/bash

PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH

# This script is used to query metadata.

[ "$(cloud_type.sh)" = "aws" ] && ec2-metadata $@
[ "$(cloud_type.sh)" = "azure" ] && azure-metadata $@

exit 0

