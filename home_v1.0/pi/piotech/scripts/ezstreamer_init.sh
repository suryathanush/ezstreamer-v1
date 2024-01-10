#!/bin/bash

sleep 10

sudo supervisorctl stop all

sleep 30

#Turn off HDMI
sudo tvservice --off

#Turn off USB
sudo uhubctl/./uhubctl -a 0 -l 2

#Turn off LEDs
sudo sh -c 'echo 0 > /sys/class/leds/led1/brightness'
sudo sh -c 'echo 0 > /sys/class/leds/led0/brightness'

sudo supervisorctl stop all

cd /home/pi/piotech/scripts/
#nohup python3 -u ezstreamer_rpi4_0.0.1.py 
#nohup python3 -u ezstreamer_rpi4_0.0.1.py >> /home/pi/piotech/logs/cronlog 2>&1 
nohup python3 -u ezstreamer_rpi4.py >> /home/pi/piotech/logs/cronlog 2>&1 
