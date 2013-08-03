#!/bin/bash

cd `dirname "$0"`
./server/ffbackup-server -c ca.crt -e server.crt -k server.key -P server -v
