#!/bin/bash

links=()
x=0

filename="/home/pi/piotech/config/stream3_config.txt"
while IFS= read -r line
do
  #echo "$line"

  #[0]=rtsp, [1]=rtmp, [2]=audio 
  links[x]="$line"

  #echo ${links[x]}

  ((x=x+1))
done < "$filename"

if [ ${links[2]} -eq 1 ]; then
  ffmpeg -rtsp_transport tcp -i ${links[0]} -f lavfi -i anullsrc -c:v copy -c:a aac -strict -2 -b:a 64k -progress /tmp/ffmpeg_stream3.log -f flv ${links[1]}
else
  ffmpeg -rtsp_transport tcp -i ${links[0]} -c:v copy -c:a aac -ar 44100 -strict -2 -b:a 64k -progress /tmp/ffmpeg_stream3.log -filter:a loudnorm -f flv ${links[1]}
fi
