#!/usr/bin/env bash


tcpdump -i eth0 -w /output/dump.pcap &

java -jar /apps/TLS-Testsuite.jar $@