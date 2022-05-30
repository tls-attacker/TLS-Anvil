#!/usr/bin/env bash


tcpdump -i lo -w ./output/dump.pcap &

java -jar /apps/TLS-Testsuite.jar $@