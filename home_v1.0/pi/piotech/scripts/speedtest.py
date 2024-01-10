import os
import re
import subprocess
import time

#python 2.7.16
#response = subprocess.Popen('speedtest-cli --simple', shell=True, stdout=subprocess.PIPE).stdout.read()

#python 3.7.3
#sub_response = subprocess.Popen('speedtest-cli --simple', shell=True, stdout=subprocess.PIPE).stdout.read()
#sub_response = subprocess.Popen('speedtest-cli --csv', shell=True, stdout=subprocess.PIPE).stdout.read()
#response = sub_response.decode('utf-8')

sub_response = subprocess.Popen('speedtest-cli --csv', shell=True, stdout=subprocess.PIPE).stdout.read()

#ping = re.findall('Ping:\s(.*?)\s', response, re.MULTILINE)
#download = re.findall('Download:\s(.*?)\s', response, re.MULTILINE)
#upload = re.findall('Upload:\s(.*?)\s', response, re.MULTILINE)

#ping[0] = ping[0].replace(',', '.')
#download[0] = download[0].replace(',', '.')
#upload[0] = upload[0].replace(',', '.')

#try:
#    if os.stat('/home/pi/speedtest/speedtest.csv').st_size == 0:
#        print ('Date,Time,Ping (ms),Download (Mbit/s),Upload (Mbit/s)')
#except:
#    pass

#print ('{},{},{},{},{}'.format(time.strftime('%m/%d/%y'), time.strftime('%H:%M'), ping[0], download[0], upload[0]))
print (sub_response)
