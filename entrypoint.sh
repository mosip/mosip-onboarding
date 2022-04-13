#!/bin/sh
# entrypoints.sh 

echo Start a simple http server
http-server --proxy http://localhost:8080? > http.log 2>&1 &
echo Onboarding default partners
./default.sh
echo Onboarding completed! 
echo Reports available at http://localhost:8080/reports
echo Restart this docker if you wish to run onboarding again
sleep 31536000

