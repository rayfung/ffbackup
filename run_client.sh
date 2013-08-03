#!/bin/bash

cd `dirname "$0"`
./client/ffbackup-client -c ca.crt -e client.crt -k client.key
