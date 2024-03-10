#!/usr/bin/env bash

make clean
make

echo -ne "zprava" | ./kry -c
echo -ne "zprava" | ./kry -s -k heslo
echo -ne "zprava" | ./kry -v -k heslo -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
echo $?
echo -ne "message" | ./kry -v -k password -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
echo $?
echo -ne "zprava" | ./kry -e -n 5 -a ==message -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e