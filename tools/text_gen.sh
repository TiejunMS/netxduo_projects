#!/bin/bash

rm -f test.txt
for i in {0..1048576}
do
  printf "|%06X\n" $i >> test.txt
done