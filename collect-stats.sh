#!/bin/bash

echo "noproxy,proxy" > stats.csv

for i in {1..500}
do
  echo "Collecting stats for $i"
  go run ./e2e >> stats.csv
done
