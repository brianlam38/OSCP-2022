#!/bin/bash

########################################
# Automated enumeration using Rpcclient
########################################

echo "########################################################################"
echo "This script requires the target to have SMB guest login available."
echo "Otherwise, provide a set of credentials within the script."
echo "########################################################################"
echo ""

# List of useful rpcclient commands
declare -a arr=(\
	"srvinfo" \
	"enumdomains" \
	"querydominfo" \
	"enumdomusers" \
	"enumdomgroups" \
	"getdompwinfo")

# Execute rpcclient commands
for i in "${arr[@]}"; do
	echo "rpcclient> $i"
	rpcclient -U "" -N 10.11.1.136 -c $i
	echo ""
done

echo "########################################################################"
echo "Enumeration complete.\n"
echo "Follow up queries you can run manually, depending on the results:"
echo "- querygroup 0x200"
echo "- querygroupmem 0x200"
echo "- queryuser 0x3601"
echo "- getusrdompwinfo 0x3601"
echo "########################################################################"

