#!/bin/sh
# entrypoints.sh 

echo Start a simple http server
http-server --proxy http://localhost:8080? > http.log 2>&1 &
echo Onboarding default partners
./default.sh
sleep 10000

