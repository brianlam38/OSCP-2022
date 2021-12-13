#!/bin/bash
while read line; do
    echo "Testing $line"; snmpwalk -c $line -v 2c $1
done < $2
