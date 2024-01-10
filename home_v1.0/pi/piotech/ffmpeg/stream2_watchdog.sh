#!/bin/bash

echo Starting stream2 watchdog. Waiting 20 seconds for ffmpeg to initialize...
sleep 20

filename="/home/pi/piotech/config/stream2_watchdog_config.txt"
while IFS= read -r line
do
  #echo "$line"

  #[0]=bitrate, [1]=fps, [2]=runtime
  links[x]="$line"

  #echo ${links[x]}

  ((x=x+1))
done < "$filename"

while :
do
     echo !!!!!!!!!!!!
     #timestamp 
     TIMESTAMP_str_1=`ls -l --full-time /tmp/ffmpeg_stream2.log`
     echo $TIMESTAMP_str_1

     #runtime
     RT_str_1=`grep out_time_ms= /tmp/ffmpeg_stream2.log | tail -1`
     echo $RT_str_1

     echo waiting 30 seconds until next check
     sleep 30

     #timestamp
     TIMESTAMP_str_2=`ls -l --full-time /tmp/ffmpeg_stream2.log`
     echo $TIMESTAMP_str_2
     if [ "$TIMESTAMP_str_1" = "$TIMESTAMP_str_2" ]; then
          echo No log changes detected, restarting ffmpeg process and waiting 20 seconds to initialize
          supervisorctl restart stream2 
          sleep 20
     else
          echo Log timestamp changed, check runtime

          #runtime
          RT_str_2=`grep out_time_ms= /tmp/ffmpeg_stream2.log | tail -1`
          echo $RT_str_2
          if [ "$RT_str_1" = "$RT_str_2" ]; then
               echo No runtime changes detected, restarting ffmpeg process and waiting 20 seconds to initialize
               supervisorctl restart stream2 
               sleep 20
          else
               echo runtime changed, check runtime threshold

               #slice integer runtime after out_time_ms= string
               RT_num=${RT_str_2:12}
               echo $RT_num

               #compare runtime against max
               if [ $RT_num -gt ${links[2]} ]; then
                    echo runtime gt ${links[2]} seconds, restarting ffmpeg process and waiting 20 seconds to initialize
                    supervisorctl restart stream2 
                    sleep 20
               else
                    echo runtime lt ${links[2]} seconds, check bitrate

                    #bitrate
                    BR_str=`grep bitrate= /tmp/ffmpeg_stream2.log | tail -1`
                    echo $BR_str

                    #find the str prior the decimal point
                    PRIOR_DECIMAL_POINT="${BR_str%.*}"
                    #echo $PRIOR_DECIMAL_POINT

                    #slice integer bitrate after bitrate= string
                    BR_num=${PRIOR_DECIMAL_POINT:8}
                    echo $BR_num

                    #compare bitrate against min
                    if [ $BR_num -lt ${links[0]} ]; then
                         echo bitrate lt ${links[0]} kbits/s, restarting ffmpeg process and waiting 20 seconds to initialize
                         supervisorctl restart stream2 
                         sleep 20
                    else
                         echo bitrate gt ${links[0]} kbits/s, check fps

                         #fps
                         FPS_str=`grep fps= /tmp/ffmpeg_stream2.log | tail -1`
                         echo $FPS_str

                         #find the str prior the decimal point
                         PRIOR_DECIMAL_POINT="${FPS_str%.*}"
                         #echo $PRIOR_DECIMAL_POINT

                         #slice integer fps after fps= string
                         FPS_num=${PRIOR_DECIMAL_POINT:4}
                         echo $FPS_num

                         #compare fps against min
                         if [ $FPS_num -lt ${links[1]} ]; then
                              echo fps lt ${links[1]}, restarting ffmpeg process and waiting 20 seconds to initialize
                              supervisorctl restart stream2 
                              sleep 20
                         else
                              echo fps gt ${links[1]}, all good
                         fi
                    fi
               fi
          fi
     fi
done
