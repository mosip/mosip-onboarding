#!/bin/sh
# entrypoints.sh 


echo Onboarding default partners
./default.sh
./upload-reports.sh
echo Onboarding completed!

