'''
Module: ezstreamer_rpi4_0.0.F.py
Description: Controls communications and file processing to and from server 
             
Copyright 2020 pIoTech

Author: Kris Modar

Creation Date: 05/02/2020
Release 0.0.D: ??/??/2021
'''

import sys
import datetime
import time
import os
import subprocess
import logging
import RPi.GPIO as GPIO
import fnmatch
from shutil import copyfile
from shutil import move
import netifaces as ni
from netaddr import IPAddress
from ftplib import FTP_TLS
from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib
import binascii
import simplejson as json
import random

_old_makepasv = FTP_TLS.makepasv    
    
'''Configure the GPIO'''
GPIO.setmode(GPIO.BCM)    

GPIO.setup(23, GPIO.OUT)  #Status
GPIO.setup(24, GPIO.OUT)  #Stream
GPIO.setup(26, GPIO.OUT)  #Cloud
GPIO.output(23, GPIO.LOW) #Status off
GPIO.output(24, GPIO.LOW) #Stream off
GPIO.output(26, GPIO.LOW) #Cloud off

#LOGGING_LEVEL = logging.INFO
#LOGGING_LEVEL = logging.DEBUG
#LOGGING_LEVEL = logging.WARNING
#LOGGING_LEVEL = logging.ERROR
#LOGGING_LEVEL = logging.CRITICAL

'''default logging'''
logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s", datefmt='%Y-%m-%d %H:%M:%S')

def logging_config(level):
    
    ll_list = ["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"]
    
    epoch_time = time.time()
    
    log_fp = "../transfer/log/log_%s.txt" % (str(int(epoch_time)))
#     print(log_fp)
    level_str = "level=logging." + ll_list[level]
#     print(level_str)
    logging.basicConfig(level_str, filename=log_fp, filemode="a")
    
def update_sys_time():
    
    result = "Failed"
    
    '''update our datetime'''
    ntp_stop = "sudo service ntp stop"
    try:
        response = subprocess.check_output(ntp_stop, shell=True, timeout=45)
        logging.debug("ntp_stop = %s" % response)
    except:
        response = "Failed_NtpStop"
        logging.debug("Failed_NtpStop")
    
    ntp_sync = "sudo ntpdate 216.239.35.0"
    try:
        sync_response = subprocess.check_output(ntp_sync, shell=True, timeout=45)
        logging.debug("ntp_sync = %s" % sync_response)
    except:
        sync_response = b"Failed_NtpSync"
        logging.debug("Failed_NtpSync")
    
    ntp_start = "sudo service ntp start"
    try:
        response = subprocess.check_output(ntp_start, shell=True, timeout=45)
        logging.debug("ntp_start = %s" % response)
    except:
        response = "Failed_NtpStart"
        logging.debug("Failed_NtpStart")          
    
    if b"ntpdate" in sync_response:  
        result = "Success"
        
    return result  

def sanity_check(stream_cnt):
    p_dict = {"sleep":"root", "ezstreamer":"pi",
                    "supervisord":"root", "ffmpeg":"root"}
    pcnt_dict = {"sleep":stream_cnt, "ezstreamer":4,
                    "supervisord":1, "ffmpeg":5*stream_cnt}
    reboot_bin = False
    
    '''check our process count and reboot if we go haywire'''
    for key, value in p_dict.items():
        p_str = "pgrep -U " + value + " -f " + key + " | wc -l"
        logging.debug(p_str)
        try:
            p_cnt = int(subprocess.check_output(p_str, shell=True, timeout=45))
            logging.debug("%s = %d" % (key, p_cnt))
            
            if p_cnt > pcnt_dict[key]:
                logging.error("Rebooting - %s = %d" % (key, p_cnt))
                reboot_bin = True
                break
        except:
            logging.warning("Failed to collect sleep count")
    
    if (reboot_bin):
        ezs_reboot()
                    
    return reboot_bin

def ezs_reboot():
    
    logging.warning("Issue reboot")
    
    '''stop all streams and delete config files'''
    response = stream_control("stop_all", None)
    destroy_stream_config_files()
    '''init the number of streams to run'''
    stream_cnt = 0
    
    '''build the log file and wait a touch for save'''
    build_log_file()
    time.sleep(3)
    
    reboot_str = "sudo reboot"
    try:
        response = subprocess.check_output(reboot_str, shell=True, timeout=45)
        logging.debug(response)
    except:
        logging.warning("Failed to reboot")
        
def new_makepasv(self):
    host,port = _old_makepasv(self)
    logging.debug("old_makepasv:")
    logging.debug(host)
    logging.debug(port)    
    host = self.sock.getpeername()[0]
    logging.debug("new_makepasv:")
    logging.debug(host)
    logging.debug(port)
    return host,port
    
def create_ftps_instance(ezs_id, cpu_sn):
    ftps = None
    ftpsInstanceContinue = False
    
    FTP_TLS.makepasv = new_makepasv
    
    '''bring up and ftps instance'''
    try:
        ftps = FTP_TLS("ftp.ez-streamer.com", timeout=30)
        #except Exception as e:  #you can specify type of Exception also
        #    print (e.output)
        if ftps != None:
#             ftps.set_debuglevel(2)
            GPIO.output(26, GPIO.HIGH) #cloud
            ftpsInstanceContinue = True
    except:
        logging.warning("establish_ftps - ftps instance exception")
        ftpsInstanceContinue = False
        
    '''if we have an instance then setup the connection'''    
    if ftpsInstanceContinue == True:
        try:
            '''Set up a secure control connection by using TLS or SSL'''
            ftps.auth()
        except:
            logging.warning("establish_ftps - ftps auth exception")
            ftpsInstanceContinue = False
    
    if ftpsInstanceContinue == True:        
        try:
            '''Set up secure data connection.'''
            ftps.prot_p()
        except:
            logging.warning("establish_ftps - ftps prot_p exception")
            ftpsInstanceContinue = False            
    
    '''if we have an instance then login'''    
    if ftpsInstanceContinue == True:
        logging.debug("ftps instance success")
        try:        
            ftps.login(ezs_id + '@ez-streamer.com', ezs_id + '@@' + cpu_sn)
        except:
            logging.warning("establish_ftps - ftps login failure")
            ftpsInstanceContinue = False
            
    '''if we have an instance, connection and are logged in'''    
    if ftpsInstanceContinue == True:
        logging.debug("ftps login success")
        
    if ((ftpsInstanceContinue == False) and (ftps != None)):
        ftps = destroy_ftps(ftps)
        
    return ftps

def destroy_ftps(ftps):
    
    if (ftps != None):
        try:
            ftps.quit()
        except:
            logging.warning("destroy_ftps - ftps quit failure")
            
        GPIO.output(26, GPIO.LOW) #cloud   
        ftps = None
        
    return ftps

def network_ping_test(directed_interface=None):
    max_comms_attempts = 2
    max_ping_attempts = 1
    comms_retries = 0
    interface = None
    ip_address = None
    netmask = None
    result = None
    response = None
    
    logging.debug("network_ping_test()..")
     
    '''is the ethernet up?'''
    logging.debug(time.time())
    
    GPIO.output(26, GPIO.HIGH) #cloud on
    
    '''if the ping is southbound'''
    if ((directed_interface != None) and (directed_interface == "eth1")): 
        interface = directed_interface
        ip_address = "10.56.173.2"
        ping_test = "ping -c 1 -I " + interface + " " + ip_address         
    
    while comms_retries < max_comms_attempts:
        ping_retries = 0
        network_restart = False
        
        '''if the ping is not southbound'''
        if ip_address != "10.56.173.2":
            ping_test = ""
            
            '''find an active northbound interface'''
            for interface in ni.interfaces():
                if "lo" not in interface:
                    if "eth1" not in interface:
                        if directed_interface != None:
                            interface = directed_interface
                        try:
                            ip_address = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
                            netmask = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
                            logging.debug("interface " + interface + " appears to be active")
                            
                            ping_test = "ping -c 1 -I " + interface + " ez-streamer.com"
                            
                            '''print our mac and current ip address at the end of the current crontab file'''
                            logging.debug(ni.ifaddresses(interface)[ni.AF_LINK][0]['addr'])
                            logging.debug(ni.ifaddresses(interface)[ni.AF_INET][0]['addr'])
                            logging.debug(ni.ifaddresses(interface)[ni.AF_INET][0]['netmask'])
                                                        
                            break
                        except:
                            logging.debug("interface " + interface + " not active")
                            
                            if directed_interface != None:
                                break
                            else:
                                continue
                                                 
        if "ping" in ping_test:         
            '''Attempt the ftp server connection on the active interface'''
            while ping_retries < max_ping_attempts:
                try:
                    logging.debug("try a ping..")
                    GPIO.output(23, GPIO.HIGH) #status on
                    time.sleep(1)
                    response = subprocess.check_output(ping_test, shell=True, timeout=45)
                    GPIO.output(23, GPIO.LOW) #status off
                    logging.debug (response)
                    if b"bytes from" in response: 
                        logging.debug("ping test successful - " + interface + " is up!")
                        result = str(interface)
                        break
                    else:
                        logging.warning(interface + " up, but ping failed!!")
                        ping_retries += 1
                        time.sleep(2)
                        continue
                except:
                    GPIO.output(23, GPIO.LOW) #status off   
                    logging.debug(interface + " not up!!")
                    network_restart = True
                    break             
#                 else:
#                     logging.warning(interface + " not up!!  try ping/else??")
#                     network_restart = True
                    
            if ping_retries >= max_ping_attempts:
                logging.warning("max ping attempts for " + interface + " exceeded!!")
                network_restart = True                   
        else:
            network_restart = True

        if network_restart == True:
            if "eth1" in interface:
                response = dhcp_server_control("status")
                try:
                    if b"(running)" not in response:
                        '''restart the isc-dhcp-server''' 
                        logging.warning("restart isc-dhcp-server service!!")                
                        response = dhcp_server_control("restart")
                    else:
                        logging.warning("isc-dhcp-server service running but ping to camera failed!!")
                except:
                    logging.warning("isc-dhcp-server service running but ping to camera failed!! - Except!! - Restart!!")
                    response = dhcp_server_control("restart")     
            else:
                logging.debug("restart network service!!")
                response = subprocess.check_output("sudo service networking restart", shell=True, timeout=45)  
                 
            time.sleep(7)
            comms_retries += 1
        else:
            break
        
    if comms_retries >= max_comms_attempts:
        logging.debug("max comms attempts for " + interface + " exceeded!!")
       
    GPIO.output(26, GPIO.LOW) #cloud off
            
    return result, ip_address, netmask
    
def ftps_files(type, ezs_id, cpu_sn, filename=None): 
    ftps = None 
    ftpsSessionContinue = False
    response = 0
    putFileList = []
    server_file_list = []
    local_file_list = []
    local_file = ""
    max_retries = 2
    max_retries_counter = 0
    storResult = ""
    retrResult = None
    
    logging.debug("ftps_files")
    logging.debug("type = %s" % type)                 
   
    if type == "auth":
        my_work_file_path = "../transfer/auth/"
        direction = "put"
        ftpsSessionContinue = True
    elif type == "stat":
        my_work_file_path = "../transfer/stat/"
        direction = "put"
        ftpsSessionContinue = True
    elif type == "log":
        my_work_file_path = "../transfer/log/"
        direction = "put"
        ftpsSessionContinue = True
    elif type == "cfg":
        my_work_file_path = "../transfer/cfg/"
        direction = "get"
        match_str = "cfg_*.txt"
        ftpsSessionContinue = True
    elif type == "cfg_del_all":
        direction = "delete"
        match_str = "cfg_*.txt"
        ftpsSessionContinue = True
    elif type == "auth_del_all":
        direction = "delete"
        match_str = "auth_*.txt"
        ftpsSessionContinue = True                  
    elif type == "update":
        my_work_file_path = "../transfer/update/"
        direction = "get"
        if filename is not None:
            match_str = filename        
            ftpsSessionContinue = True
        else:
            ftpsSessionContinue = False
            logging.warning("ftps_files - update filename is None")            
    else:
        ftpsSessionContinue = False
        logging.warning("ftps_files - Invalid type")
        
    if ftpsSessionContinue == True: 
        if direction == "put":
            '''search for all files that need uploaded'''
            for path, directories, files in os.walk(my_work_file_path):
                logging.debug(path)
        #             print directories
        #             print files
                for putfile in files:
                    putFileList.append(putfile)

            if len(putFileList) > 0:
                logging.debug("files that need uploaded:")
                logging.debug(putFileList)            
                ftpsSessionContinue = True
            else:
                ftpsSessionContinue = False
                logging.debug("file list empty!!")
                
    '''if direction = get or we have files to put'''            
    if ftpsSessionContinue == True:
        while max_retries_counter < max_retries:
            '''bring up and ftps instance'''
            ftps = create_ftps_instance(ezs_id, cpu_sn)

            '''if we are logged in upload the files'''                 
            if ftps != None:
                if direction == "put":            
                    '''walk the putFileList'''
                    for currentPutFile in putFileList:
                        GPIO.output(23, GPIO.HIGH) #status on
                        fileURL = path + currentPutFile
                        try:
                            current_file = open(fileURL, "rb")
                        except:
                            logging.warning("putData - open current_file exception")
                        if current_file:
                            uploadCmd = "STOR " + currentPutFile
                            try:
                                storResult = ftps.storbinary(uploadCmd, current_file)                              
                            except:
                                logging.warning("putData - ftps.storbinary exception")
                            try:    
                                current_file.close()
                            except:
                                logging.warning("putData - close current_file exception")
                                
                        if "226" in storResult:
                            
                            '''delete the local data file after upload to save space on the pi'''
                            try:
                                os.remove(fileURL)
                            except:
                                logging.warning("putData - os.remove exception")
                                   
                            response += 1
                            
                        GPIO.output(23, GPIO.LOW) #status off
                            
                    logging.debug("putData - %d files uploaded" % response)
                            
                elif ((direction == "get") or (direction == "delete")):
                    GPIO.output(23, GPIO.HIGH) #status on
                    try:
                        ftps.sendcmd("TYPE I")
                    except:
                        logging.warning("get_deleteData - ftps.sendcmd exception - TYPE I")
                    
                    '''list the files in our server ftps folder'''
                    try:                
                        ftps.retrlines("NLST",server_file_list.append)
                    except:
                        logging.warning("get_deleteData - ftps.retrlines exception - NLST")
                        
                    logging.debug(server_file_list)
                    GPIO.output(23, GPIO.LOW) #status off
                    for server_file in server_file_list:
                        GPIO.output(23, GPIO.HIGH) #status on
                        if fnmatch.fnmatch(server_file, match_str):
                            logging.debug("match!!!")
                            logging.debug (server_file)
                            if direction == "get":
                                local_file = my_work_file_path + server_file
                                try:
                                    retrResult = ftps.retrbinary("RETR " + server_file, open(local_file, "wb").write)
                                except:
                                    logging.warning("getData - ftps.retrbinary exception - RETR")
                                    retrResult = None
                                    
                                #if(ftps.retrbinary("RETR " + server_file, open(local_file, "wb").write)):
                                if retrResult:
                                    local_file_list.append(server_file)
                            try:        
                                ftps.delete(server_file)
                            except:
                                logging.warning("deleteData - ftps.delete exception - server_file")
                                
                        GPIO.output(23, GPIO.LOW) #status off                  
                else:    
                    logging.warning("ftps_files - Invalid direction")
                                       
                destroy_ftps(ftps)
                break
            
            '''if we are here then we failed - ftpsSessionContinue == False for some reason'''
            max_retries_counter += 1
            
    if direction == "get": 
        return local_file_list
    else:
        return response

def retrieve_cfg_files(ezs_id, cpu_sn):
    local_file_list = []
    timestamp_list = []
    file_list_sorted = []
        
    logging.debug("retrieve_cfg_files")
    
    '''get the file(S)'''
    local_file_list = ftps_files("cfg", ezs_id, cpu_sn, None)
        
    '''sort the list by timestamp ASC (oldest first), rebuild file list and return the sorted list'''
    if (len(local_file_list) > 0):
        logging.debug(local_file_list)
        for file in local_file_list:
            timestamp_list.append(file.split(".")[0].split("_")[1])
        timestamp_list.sort()
        for timestamp in timestamp_list:
            full_filename = "cfg_" + timestamp + ".txt"
            file_list_sorted.append(full_filename)
        logging.debug(file_list_sorted)
        
    return file_list_sorted
    
def build_stream_config_files(cmd_service, cmd_rtsp_link, cmd_silent_audio,
                              cmd_min_br, cmd_min_fps, cmd_max_runtime,
                              cmd_url_link, cmd_stream_key):
    
    stream_ctrl_int = 0;
    
    '''we should have all the pieces now - process the command'''
    if (("rtsp://" in cmd_rtsp_link) and 
        (("rtmp://" in cmd_url_link) or ("rtmps://" in cmd_url_link)) and 
        ("-" in cmd_stream_key)):
            
        try:
            fp_stream_config = open("../config/" + cmd_service + "_config.txt", "w")
        except:
            logging.warning("failed to open stream config file")
        
        try:
            fp_stream_config.write(cmd_rtsp_link + "\n")
        except:
            logging.warning("failed to write cmd_rtsp_link")
            
        try:
            fp_stream_config.write(cmd_url_link + cmd_stream_key + "\n")
        except:
            logging.warning("failed to write cmd_url_link and cmd_stream_key")
            
        try:
            fp_stream_config.write(cmd_silent_audio + "\n")
        except:
            logging.warning("failed to write cmd_silent_audio")
            
        try:
            fp_stream_config.close()
        except:
            logging.warning("failed to close stream config file")
        
        stream_ctrl_int += 1
    else:
        logging.warning("build_stream_config_files - Invalid stream parameters - " + cmd_service + "- check rtsp, rtmp, '-'")

        
    if stream_ctrl_int == 1:     
        try:
            fp_stream_watchdog = open("../config/" + cmd_service + "_watchdog_config.txt", "w")
        except:
            logging.warning("failed to open stream watchdog config file")
            
        if int(cmd_min_br) < 1:
            cmd_min_br = "1"     
        try:
            fp_stream_watchdog.write(cmd_min_br + "\n")
        except:
            logging.warning("failed to write cmd_min_br")
            
        if int(cmd_min_fps) < 1:
            cmd_min_fps = "1"    
        try:
            fp_stream_watchdog.write(cmd_min_fps + "\n")
        except:
            logging.warning("failed to write cmd_min_fps")
            
        try:
            fp_stream_watchdog.write(cmd_max_runtime + "\n")
        except:
            logging.warning("failed to write cmd_max_runtime")            
            
        try:
            fp_stream_watchdog.close()
        except:
            logging.warning("failed to close stream watchdog config file")
            
        stream_ctrl_int += 1
        
    if stream_ctrl_int > 1:   
        '''restart the ffmpeg scripts'''
        response = stream_control("restart", cmd_service)
        if response == 0:
            error_str = "Failed to restart " + cmd_service
            logging.warning(error_str)            
    else:
        '''stop the ffmpeg scripts'''
        response = stream_control("stop", cmd_service)
        if response == 0:
            error_str = "Failed to stop " + cmd_service
            logging.warning(error_str)
            
def destroy_stream_config_files():
    
    response = 0
    
    try:
        destory_all_str = "rm ../config/stream*"
        subprocess.check_output(destory_all_str, shell=True, timeout=45)
        response = 1
    except:
        logging.debug("Failed to destroy all stream config files")
        
    return response

def de_crypto(cpu_sn, ezs_id, data):
    clean = ""
    
    passphrase = hashlib.sha256(bytes(cpu_sn + "/#pIo/" + ezs_id + "\Tech$\!!", 'utf8')).hexdigest()

    try:
        unpad = lambda s : s[:-s[-1]]
        key = binascii.unhexlify(passphrase)
        
        encrypted = json.loads(base64.b64decode(data).decode('ascii'))
        encrypted_data = base64.b64decode(encrypted['data'])
        iv = base64.b64decode(encrypted['iv'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        clean = unpad(decrypted).decode('ascii').rstrip()
    except Exception as e:
        logging.warning("Cannot decrypt datas...")
        logging.warning(e)
        
    return clean

def build_auth_file(ezs_id, cpu_sn, sd_sn, FW_VERSION):
    baf_continue = True
    
    '''auth directory should be clean'''
    for path, directories, files in os.walk("../transfer/auth/"):                
        for f in files:
            os.remove(os.path.join(path, f))
    
    epoch_time = time.time()
    
    auth_fp = "../transfer/auth/auth_%s.txt" % (str(int(epoch_time)))
    logging.debug(auth_fp)
    
    try:
        fp_auth = open(auth_fp, "w")
    except:
        logging.warning("failed to open auth file")
        baf_continue = False
    
    if baf_continue:    
        try:
            fp_auth.write("AT+SRC=" + ezs_id + "\n")
        except:
            logging.warning("build_auth_file - failed to write src command")
            baf_continue = False
            
    if baf_continue:    
        try:
            fp_auth.write("AT+SRV=0\n")
        except:
            logging.warning("build_auth_file - failed to write srv command")
            baf_continue = False
    
    if baf_continue:        
        try:
            fp_auth.write("AT+ACT=0\n") #authenticate
        except:
            logging.warning("build_auth_file - failed to write act command")
            baf_continue = False
    
    if baf_continue:    
        try:
            fp_auth.write("AT+CMD#=3\n")
        except:
            logging.warning("build_auth_file - failed to write cmd# command")
            baf_continue = False

    if baf_continue:        
        encrypted_str = en_crypto(cpu_sn, ezs_id, cpu_sn)
        write_str = "AT+CMD=%s\n" % (encrypted_str) 
        try:
            fp_auth.write(write_str)
        except:
            logging.warning("build_auth_file - failed to write cmd1 command")
            baf_continue = False  

    if baf_continue:             
        encrypted_str = en_crypto(cpu_sn, ezs_id, sd_sn)
        write_str = "AT+CMD=%s\n" % (encrypted_str)  
        try:
            fp_auth.write(write_str)
        except:
            logging.warning("build_auth_file - failed to write cmd2 command")
            baf_continue = False
            
    if baf_continue:             
        write_str = "AT+CMD=%s\n" % (FW_VERSION)  
        try:
            fp_auth.write(write_str)
        except:
            logging.warning("build_auth_file - failed to write cmd3 command")
            baf_continue = False
            
    if baf_continue:    
        try:
            fp_auth.write("AT+EOC\n")
        except:
            logging.warning("build_auth_file - failed to write eoc command")
            baf_continue = False
     
    if baf_continue:   
        try:
            fp_auth.write("AT+EOF\n")
        except:
            logging.warning("build_auth_file - failed to write eof command")
            baf_continue = False    
    
    if fp_auth:    
        try:
             fp_auth.close()
        except:
            logging.warning("build_auth_file - failed to close auth file")
            baf_continue = False
    
    if ((not baf_continue) and (fp_auth)):
        '''delete the bad/partial file'''
        os.remove(fp_auth)
                
    return baf_continue

def en_crypto(cpu_sn, ezs_id, data):
    
    passphrase = hashlib.sha256(bytes(cpu_sn + "/#pIo/" + ezs_id + "\Tech$\!!", 'utf8')).hexdigest()
    
    try:
        key = binascii.unhexlify(passphrase)
        pad = lambda s : s+chr(16-len(s)%16)*(16-len(s)%16)
        
        iv = Random.get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_64 = base64.b64encode(cipher.encrypt(pad(data))).decode('ascii')
        iv_64 = base64.b64encode(iv).decode('ascii')
        json_data = {}
        json_data['iv'] = iv_64
        json_data['data'] = encrypted_64
        clean = base64.b64encode(json.dumps(json_data).encode('ascii'))
        clean_str = clean.decode('ascii')
    except Exception as e:
        logging.warning("Cannot encrypt datas...")
        logging.warning(e)
        exit(1)
        
    return clean_str
    
def stream_control(action, cmd_service=None):
    response = 0
    
    if ((action == "restart") or (action == "stop") or (action == "start")):
        if cmd_service != None:
            '''restart the ffmpeg scripts'''
            try:
                supervisorctl_str = "sudo supervisorctl " + action + " " + cmd_service
                response = subprocess.check_output(supervisorctl_str, shell=True, timeout=45)
                logging.debug(response)
            except:
                logging.warning("Failed to " + action + " " + cmd_service)
            
            if response:
                try:    
                    supervisorctl_str = "sudo supervisorctl " + action + " " + cmd_service + "_watchdog"
                    response = subprocess.check_output(supervisorctl_str, shell=True, timeout=45)
                    logging.debug(response)
                except:
                    logging.warning("Failed to " + action + " " + cmd_service + "watchdog")
        else:
            logging.warning("stream_control - cmd_service can't be None")
    elif (action == "stop_all"):
        try:
            supervisorctl_str = "sudo supervisorctl stop all"
            response = subprocess.check_output(supervisorctl_str, shell=True, timeout=45)
            logging.debug(response)
        except:
            logging.warning("Failed to stop all")
    else:
        logging.warning("stream_control - Invalid action")  
    
    return response

def build_stat_file(ezs_id, interface, ip_address, cpu_temp, stream_cnt, srv_list):
    result = {}
    bsf_continue = True
    status_key_list = ["status", "bitrate", "fps", "out_time_us", "dup_frames", "drop_frames"]
    srv_list_index = 0
            
    if ((interface != None) and (ip_address != None)):    
            
        epoch_time = time.time()
        localtime = time.localtime(epoch_time)
        
        stat_fp = "../transfer/stat/stat_%s.txt" % (str(int(epoch_time)))
        logging.debug(stat_fp)
        
        try:
            fp_stat = open(stat_fp, "w")
        except:
            logging.warning("failed to open stat file")
            bsf_continue = False
        
        if bsf_continue:    
            try:
                fp_stat.write("AT+SRC=" + ezs_id + "\n")
            except:
                logging.warning("build_stat_file - failed to write src command")
                bsf_continue = False
                
        while srv_list_index <= stream_cnt:       
                
            if bsf_continue:
                svr_str = "AT+SRV=%d\n" % srv_list_index   
                try:
                    fp_stat.write(svr_str)
                except:
                    logging.warning("build_stat_file - failed to write srv command")
                    baf_continue = False
                    break
            
            if bsf_continue:  
                try:
                    fp_stat.write("AT+ACT=2\n") #status
                except:
                    logging.warning("build_stat_file - failed to write act command")
                    bsf_continue = False
                    break
                           
            if bsf_continue:
                if srv_list_index == 0:    
                    try:
                        fp_stat.write("AT+CMD#=5\n")
                    except:
                        logging.warning("build_stat_file - failed to write cmd# command")
                        bsf_continue = False
                        break
                        
                    write_str = "AT+CMD=%s\nAT+CMD=%s\nAT+CMD=%s\nAT+CMD=%s\nAT+CMD=%s\nAT+EOC\n" % (
                                time.strftime("%Y-%m-%d", localtime),
                                time.strftime("%H:%M:%S", localtime),
                                interface, ip_address, cpu_temp) 
                    try:
                        fp_stat.write(write_str)
                        srv_list_index += 1
                    except:
                        logging.warning("build_stat_file - failed to write " + result[index] + " stat")
                        bsf_continue = False
                        break
                       
                elif ((srv_list_index > 0) and (srv_list_index <= 4)):
                    try:
                        fp_stat.write("AT+CMD#=6\n")
                    except:
                        logging.warning("build_stat_file - failed to write cmd# command")
                        bsf_continue = False
                        break
                    
                    GPIO.output(24, GPIO.HIGH) #stream                        
                    result = get_stat_data(srv_list[srv_list_index])
                    GPIO.output(24, GPIO.LOW) #stream
                    time.sleep(0.10)
                    
                    for index in status_key_list:
                        write_str = "AT+CMD=%s\n" % (result[index]) 
                        try:
                            fp_stat.write(write_str)
                        except:
                            logging.warning("build_stat_file - failed to write " + result[index] + " stat")
                            bsf_continue = False
                            break
                    if bsf_continue:
                        srv_list_index += 1
                        
                        '''end the command'''
                        try:
                            fp_stat.write("AT+EOC\n")
                        except:
                            logging.warning("build_stat_file - failed to write eoc command")
                            bsf_continue = False
                    else:
                        break                    
                else:
                    break
        
        if bsf_continue:
            '''end the file'''    
            try:
                fp_stat.write("AT+EOF\n")
            except:
                logging.warning("build_stat_file - failed to write eof command") 
                bsf_continue = False   
        
        if fp_stat:    
            try:
                 fp_stat.close()
                 response = 1   
            except:
                logging.warning("build_stat_file - failed to close auth file")
                
        if ((not bsf_continue) and (fp_stat)):
            '''delete the bad/partial file'''
            os.remove(fp_stat)
            
    else:
        bsf_continue = False
            
    return bsf_continue

def check_stream_status(stream_cnt, srv_list):
    result = {}
    srv_list_index = 0
    streams_running_count = 0
    
    while srv_list_index <= stream_cnt:
        
        if srv_list_index > 0:
            
            GPIO.output(24, GPIO.HIGH) #stream
            result = get_stat_data(srv_list[srv_list_index])
            GPIO.output(24, GPIO.LOW) #stream
            time.sleep(0.10)
        
            if result["status"] == "RUNNING":
                streams_running_count += 1
            
        srv_list_index += 1
        
    return streams_running_count
     
def get_stat_data(stream):
    response = None
    
    status_data = {"status":None, "bitrate":None, "fps":None, "out_time_us":None,
                   "dup_frames":None, "drop_frames":None}
    
    status_command = "sudo supervisorctl status " + stream
    try:
        response = subprocess.check_output(status_command, shell=True, timeout=45)
        status_data["status"] = (b" ".join(response.split())).split(b" ")[1].decode('utf8')
    except:    
        logging.debug("get_stat_data - failed to get " + stream + " status")
    
    '''walk the dictionay keys and get the latest stats'''    
    if status_data["status"] == "RUNNING":
        GPIO.output(23, GPIO.HIGH) #status
        for key in status_data.keys():
            if "status" not in key:
                latest_stat_command = "grep " + key + "= /tmp/ffmpeg_" + stream + ".log | tail -1" 
                try:
                    response = subprocess.check_output(latest_stat_command, shell=True, timeout=45)
                    logging.debug(response)
                    status_data[key] = response.split(b"=")[1].split(b".")[0].lstrip().rstrip().decode('utf8')
                    logging.debug(status_data[key])
                    if key == "out_time_ms":
                        status_data[key] = str(int(status_data[key]) / 1000000)
                except:    
                    logging.debug("get_stat_data - failed to get " + stream + " " + key)
                    
    time.sleep(0.10)            
    GPIO.output(23, GPIO.LOW) #status
    time.sleep(0.10)
                            
    return status_data

def get_cpu_temp():
    """
    Obtains the current value of the CPU temperature.
    :returns: Current value of the CPU temperature if successful, zero value otherwise.
    :rtype: float
    """
    # Initialize the result.
    result = 0.00
    # The first line in this file holds the CPU temperature as an integer times 1000.
    # Read the first line and remove the newline character at the end of the string.
    if os.path.isfile('/sys/class/thermal/thermal_zone0/temp'):
        with open('/sys/class/thermal/thermal_zone0/temp') as f:
            line = f.readline().strip()
        # Test if the string is an integer as expected.
        if line.isdigit():
            # Convert the string with the CPU temperature to a float in degrees Celsius.
            result = float(line) / 1000
    # Give the result back to the caller.
    return str(result)

def build_log_file():
    response = None
    
    epoch_time = time.time()
    log_fp = "../transfer/log/log_%s.txt" % (str(int(epoch_time)))
    
    if log_fp:
        copyfile("/home/pi/piotech/logs/cronlog", log_fp)
        
    '''truncate the cronlog'''
    try:
        subprocess.check_output("truncate -s 0 /home/pi/piotech/logs/cronlog", shell=True, timeout=45)
    except:
        logging.warning("Failed to truncate cronlog")
         
    return response

def manage_local_log_files(max_file_count):
    local_file_list = []
    timestamp_list = []
    keep_file_count = 0
    remove_log_file_str = ""
    
    '''get the file(S)'''
    log_file_path = "../transfer/log/"
    
    for path, directories, files in os.walk(log_file_path):
        logging.debug(path)
#       print directories
#       print files
    for file in files:
        local_file_list.append(file)
        
    '''sort the list by timestamp ASC (oldest first), rebuild file list and return the sorted list'''
    if (len(local_file_list) > 0):
        logging.debug(local_file_list)
        for file in local_file_list:
            timestamp_list.append(file.split(".")[0].split("_")[1])
        timestamp_list.sort()
        for timestamp in timestamp_list:
            full_filename_path = log_file_path + "log_" + timestamp + ".txt"
            
            if (keep_file_count < max_file_count):
                keep_file_count += 1
            else:
                try:
                    remove_log_file_str = "rm " + full_filename_path
                    subprocess.check_output(remove_log_file_str, shell=True, timeout=45)
                    response = 1
                except:
                    logging.debug("Failed to remove log file")
        
    return timestamp_list
    
def configure_wlan0(ssid, password):
    response = None
    configureWlan0Continue = False
    
    if (ssid == None and password == None):
        disable_wlan0_command = "sudo ifconfig wlan0 down"
        try:
            response = subprocess.check_output(disable_wlan0_command, shell=True, timeout=45)
        except:    
            logging.warning("configure wlan0 - failed to disable wlan0")
    else:
        enable_wlan0_command = "sudo ifconfig wlan0 up"
        try:
            response = subprocess.check_output(enable_wlan0_command, shell=True, timeout=45)
            configureWlan0Continue = True
        except:    
            logging.warning("configure wlan0 - failed to enable wlan0")
            
        if configureWlan0Continue:
            set_ssid_command = "sudo wpa_cli set_network 0 ssid '\"" + ssid + "\"'" 
            logging.debug(set_ssid_command)
            try:
                response = subprocess.check_output(set_ssid_command, shell=True, timeout=45)
            except:    
                logging.warning("configure wlan0 - failed to set ssid")
                
            if b"OK" in response:
                '''generate the psk'''
                my_psk = wpa_psk(ssid, password)[0:64].decode('utf8')
                logging.debug(my_psk)
                set_psk_command = "sudo wpa_cli set_network 0 psk '" + my_psk + "'"
                logging.debug(set_psk_command)
                try:
                    response = subprocess.check_output(set_psk_command, shell=True, timeout=45)
                except:    
                    logging.warning("configure wlan0 - failed to set psk")
            else:
                logging.warning("failed set_ssid_command")
            
            if b"OK" in response:
                save_network_config_command = "sudo wpa_cli save_config"
                try:
                    response = subprocess.check_output(save_network_config_command, shell=True, timeout=45)
                except:    
                    logging.warning("configure wlan0 - failed to save config")
            else:
                logging.warning("failed set_psk_command")
                    
            if b"OK" in response:
                network_reconfigure_command = "sudo wpa_cli -i wlan0 reconfigure"
                try:
                    response = subprocess.check_output(network_reconfigure_command, shell=True, timeout=45)
                except:    
                    logging.warning("configure wlan0 - failed to reconfigure network")
            else:
                logging.warning("failed save_network_config_command")
                    
            if b"OK" not in response:
                logging.warning("failed network_reconfigure_command")
            
            logging.debug("sleep for a few while network is coming up...") 
            time.sleep(7)
                    
    return response       
            
def wpa_psk(ssid, password):
    
    dk = hashlib.pbkdf2_hmac('sha1', str.encode(password), str.encode(ssid), 4096, 256)
    
    return (binascii.hexlify(dk))
    
def update_routes(action, interface):
    response = 0
    
    logging.debug("update_routes - action = " + action)
    logging.debug("update_routes - interface = " + interface)
    
    if action == "set":
        if interface == "wlan0":
            set_prerouting_command = "sudo iptables -A PREROUTING -t nat -i wlan0 -p tcp --dport 80 -j DNAT --to 10.56.173.2:80"
            try:
                subprocess.check_output(set_prerouting_command, shell=True, timeout=45)
            except:    
                logging.debug("update routes - failed to set prerouting")
                
            set_forward_command = "sudo iptables -t filter -I FORWARD -p tcp --destination 10.56.173.2 --destination-port 80 -j ACCEPT"
            try:
                response = subprocess.check_output(set_forward_command, shell=True, timeout=45)
            except:    
                logging.debug("update routes - failed to set forward")
                
            #save_iptables = "sudo sh -c \"iptables-save > /etc/iptables/rules.v4\""
            #try:
            #    response = subprocess.check_output(save_iptables, shell=True)
            #except:    
            #    print ("update routes - failed to save iptables")
            
    elif action == "delete":
        if interface == "eth0":
            delete_route_command = "sudo iptables -D FORWARD 1"
            try:
                response = subprocess.check_output(delete_route_command, shell=True, timeout=45)
            except:    
                logging.debug("update routes - failed to delete routing")
                
            delete_prerouting_command = "sudo iptables -D PREROUTING -t nat -i wlan0 -p tcp --dport 80 -j DNAT --to 10.56.173.2:80"
            try:
                subprocess.check_output(delete_prerouting_command, shell=True, timeout=45)
            except:    
                logging.debug("update routes - failed to delete prerouting")
                
            #save_iptables = "sudo sh -c \"iptables-save > /etc/iptables/rules.v4\""
            #try:
            #    response = subprocess.check_output(save_iptables, shell=True)
            #except:    
            #    print ("update routes - failed to save iptables")
    else:
        logging.warning("update routes - invalid action")
    
    return response

def dhcp_server_control(action):
    response = ""
    
    if action == "start":
        start_dhcp_command = "sudo service isc-dhcp-server start"
        try:
            response = subprocess.check_output(start_dhcp_command, shell=True, timeout=45)
        except:    
            logging.warning("dhcp_server_control - failed to start isc-dhcp-server")
    elif action == "stop":
        stop_dhcp_command = "sudo service isc-dhcp-server stop"
        try:
            response = subprocess.check_output(stop_dhcp_command, shell=True, timeout=45)
        except:    
            logging.warning("dhcp_server_control - failed to stop isc-dhcp-server")
    elif action == "restart":
        restart_dhcp_command = "sudo service isc-dhcp-server restart"
        try:
            response = subprocess.check_output(restart_dhcp_command, shell=True, imeout=45)
        except:    
            logging.warning("dhcp_server_control - failed to restart isc-dhcp-server")
    elif action == "status":
        status_dhcp_command = "sudo service isc-dhcp-server status"
        try:
            response = subprocess.check_output(status_dhcp_command, shell=True, timeout=45)
        except:    
            logging.warning("dhcp_server_control - failed to get isc-dhcp-server status")
    else:
        logging.warning("update dhcp_server_control - invalid action")
        
    return response

def hub_control(action, port):
    response = 0
    
    if port == "USB":
        if action == "enable":
            #Turn on USB
            enable_usb_command = "sudo uhubctl/./uhubctl -a 1 -l 2"
            logging.debug(enable_usb_command)
            try:
                response = subprocess.check_output(enable_usb_command, shell=True, timeout=45)
            except:    
                logging.warning("hub control - failed to enable usb ports")
        else:
            #Turn off USB
            disable_usb_command = "sudo uhubctl/./uhubctl -a 0 -l 2"
            logging.debug(disable_usb_command)
            try:
                response = subprocess.check_output(disable_usb_command, shell=True, timeout=45)
            except:    
                logging.warning("hub control - failed to disable usb ports")
     
    time.sleep(3)
            
    return response
        
def ssh_control(action):
    response = 0
    
    if action == "enable":
        enable_ssh_command = "sudo systemctl enable ssh"
        try:
            response = subprocess.check_output(enable_ssh_command, shell=True, timeout=45)
        except:    
            logging.warning("ssh control - failed to enable ssh")
            
        start_ssh_command = "sudo systemctl start ssh"
        try:
            response = subprocess.check_output(start_ssh_command, shell=True, timeout=45)
        except:    
            logging.warning("ssh control - failed to start ssh")        
        
    else:
        stop_ssh_command = "sudo systemctl stop ssh"
        try:
            response = subprocess.check_output(stop_ssh_command, shell=True, timeout=45)
        except:    
            logging.warning("ssh control - failed to stop ssh")        
        
        disable_ssh_command = "sudo systemctl disable ssh"
        try:
            response = subprocess.check_output(disable_ssh_command, shell=True, timeout=45)
        except:    
            logging.warning("ssh control - failed to disable ssh")
                
def hdmi_control(action):
    response = 0
    
    if action == "enable":
        enable_hdmi_command = "sudo tvservice --preferred"
        try:
            response = subprocess.check_output(enable_hdmi_command, shell=True, timeout=45)
        except:    
            logging.warning("hdmi control - failed to enable hdmi")        
        
    else:       
        disable_hdmi_command = "sudo tvservice --off"
        try:
            response = subprocess.check_output(disable_hdmi_command, shell=True, timeout=45)
        except:    
            logging.warning("hdmi control - failed to disable hdmi")
            
def nmap_control(ip_address, netmask):
    response = None
    result = 0
    cidr = None
    
    if ((ip_address != None) and (netmask != None)):
    
        cidr = str(IPAddress(netmask).netmask_bits())
            
        epoch_time = time.time()
        nmap_sub_str = "sudo nmap -oN ../transfer/log/nmap_%s.txt -sT " % (str(int(epoch_time)))
        nmap_command =  nmap_sub_str + ip_address + "/" + cidr
        try:
            response = subprocess.check_output(nmap_command, shell=True, timeout=45)
            if response:
                result = 1
        except:    
            logging.warning("nmap control - failed to execute nmap")        
     
    return response   
            
def process_update(ezs_id, cpu_sn, cmd_filename, cmd_file_sha256): 
    local_file_list = []
    result = 0
        
    logging.warning("process_update")
    
    '''get the file'''
    local_file_list = ftps_files("update", ezs_id, cpu_sn, cmd_filename)
    
    if (len(local_file_list) == 1):
        
        '''compare the hash'''
        localfile = "../transfer/update/" + local_file_list[0]
        logging.warning("process_update/localfile str - %s" % localfile)
        
        sha256_hash = hashlib.sha256()
        with open(localfile,"rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
#             print(sha256_hash.hexdigest())
        
        logging.debug("ezs calculated hash - %s" % sha256_hash.hexdigest())
        logging.debug("config hash - %s" % cmd_file_sha256)
        
        if (sha256_hash.hexdigest() == cmd_file_sha256):
           logging.warning("hashes equal...move; remove") 
           move(localfile, "ezstreamer_rpi4.py")
           result = 1
        else:
            logging.warning("process_update - hash fails")
            os.remove(localfile)
            result = 0             
    else:
        logging.warning("process_update - update file does not exist")
        result = 0
           
    return result
        
def get_sd_card_sn():
    
    sd_card_sn_str = ""
    response = None
    
    get_sn_cmd_str = "udevadm info -a -n /dev/mmcblk0 | grep -i serial"
    
    try:
        '''print("get sd card sn..")'''
        response = subprocess.check_output(get_sn_cmd_str, shell=True, timeout=45)
        '''print (response)'''
        if b"serial" in response: 
            logging.debug("get sd card sn.. - success")
            split_str = response.split(b"0x")
            sd_card_sn_str =  (split_str[1].split(b"\""))[0].decode('ascii')
            '''print(sd_card_sn_str)'''
        else:
            logging.warning("get sd card sn.. - failed not correct format")
    except:    
        logging.warning("get sd card sn.. - failed no response")
        
    return sd_card_sn_str

def get_cpu_sn():
            
    cpu_sn_str = ""
    response = None
    
    get_sn_cmd_str = "sed -n \"s/^Serial.*: //p\" /proc/cpuinfo"
    
    try:
        '''print("get sd card sn..")'''
        response = subprocess.check_output(get_sn_cmd_str, shell=True, timeout=45)
        '''print (response)'''
        if response: 
            logging.debug("get cpu sn.. - success")
            cpu_sn_str = response.rstrip().decode('ascii')
        else:
            logging.warning("get cpu sn.. - failed not correct format")
    except:    
        logging.warning("get cpu sn.. - failed no response")
        
    return cpu_sn_str
    
def main():
    
    HW_VERSION = "100"
    FW_VERSION = "0.0.F"
    
    ezs_id = ""
    cpu_sn = ""
    sd_sn = ""
    
    srv_list = [ "ezstreamer", "stream1", "stream2", "stream3", "stream4"]
    #act_list = ["configure", "restart", "authenticate", "enable_ssh", "logging", "status", None, None]
    act_list = ["authenticate", "configure", "status", "restart", "ssh", 
                "update", "logging", "nmap", "start", "stop", "kill"]
    
    pqrst = 2
    config_interval = 2
    config_interval_counter = 0
    upload_interval = 7
    upload_interval_counter = 0
    max_fail_counter = 2  #about 6.5 minutes
    max_file_count = 25
    streams_running_count = 0
    auth_sent = False
    auth_processed_counter = 12
    
    '''set our initial led state'''
#     pic_ctrl("LED", "OFF") 
    
    '''*************************************************************************************''' 
    '''State machine                                                                        '''
    '''*************************************************************************************'''
      
    CURRENT_STATE = "INIT"
    logging.debug("CURRENT_STATE = INIT")
 
    while CURRENT_STATE != "STOP":
        
        '''*****************************************************************''' 
        ''' INIT:                                                           '''
        '''                                                                 ''' 
        '''*****************************************************************'''  
        if CURRENT_STATE == "INIT":
            
            '''disable ssh'''
            ssh_control(None)
             
            '''default logging'''
#             logging_config(1)

            '''disable hdmi'''
            hdmi_control(None)
            
            '''stop all streams and delete config files'''
            response = stream_control("stop_all", None)
            destroy_stream_config_files()
            '''init the number of streams to run'''
            stream_cnt = 0

            '''disable USB ports'''
            result = hub_control("disable", "USB")
            
            cpu_sn = get_cpu_sn()
            logging.debug(cpu_sn)
            
            sd_sn = get_sd_card_sn()
            logging.debug(sd_sn)
            
            ezs_id = os.uname()[1]
            logging.debug(ezs_id)
            
            if ((cpu_sn != "") and (sd_sn != "") and (ezs_id != "")):
                CURRENT_STATE = "AUTH"
            else:
                CURRENT_STATE = "STOP"
                logging.critical("INIT FAILURE!!")
                
            '''init some things'''
            interface = None
            ip_address = None
            netmask = None
            ping_fail_counter = 0
                
        '''*****************************************************************''' 
        ''' AUTH:                                                           '''
        '''                                                                 ''' 
        '''*****************************************************************'''          
        if CURRENT_STATE == "AUTH":
            
            logging.debug("CURRENT_STATE = AUTH")
            
            while True:
                
                '''do we have an active northbound network connection'''
                interface, ip_address, netmask = network_ping_test(None)
                if ((interface != None) and (ip_address != None) and (netmask != None)):
                         
                    '''clean out our ftps folder on the server'''
                    ftps_files("cfg_del_all", ezs_id, cpu_sn, filename=None)
                    ftps_files("auth_del_all", ezs_id, cpu_sn, filename=None)
                    
                    '''set time'''
                    update_sys_time()
                    
                    '''build, upload auth file; set state; break'''        
                    result = build_auth_file(ezs_id, cpu_sn, sd_sn, FW_VERSION)
                    if result:
                        result = ftps_files("auth", ezs_id, cpu_sn, None)
                        if result:                        
                            CURRENT_STATE = "CONFIG"
                            ping_fail_counter = 0
                            config_type = None
                            auth_sent = True
                            auth_processed_counter = 12
                            
                            '''get network snapshot'''
#                             nmap_control(ip_address, netmask)
                            
                            break
                        else:
                            logging.warning("Failed to upload auth file!!")
                            ping_fail_counter += 1
                    else:
                        logging.warning("Auth file failure!!")
                        build_log_file()
                        result = ftps_files("log", ezs_id, cpu_sn, None)
                        CURRENT_STATE = "STOP"
                else:
                    logging.debug("AUTH - No Northbound Network Connection!!")
                    manage_local_log_files(max_file_count)
                    ping_fail_counter += 1
                    
                if (ping_fail_counter >= max_fail_counter):
                    logging.warning("AUTH - Exceeded ping failures of " + str(ping_fail_counter) + " - Reebooting!!")
#                     time.sleep(120)
                    ezs_reboot()
                       
                time.sleep(60)                
        
        '''*****************************************************************''' 
        ''' IDLE:                                                           '''
        ''' check sanity, collect/upload stats, rotate/upload log           ''' 
        '''*****************************************************************'''        
        if CURRENT_STATE == "IDLE":
            
            logging.debug("CURRENT_STATE = IDLE")
#             time.sleep(60)
            
            epoch_time = time.time()
            logging.debug(epoch_time)
#             '''next 1 min interval time - find the last and add 1 mins'''
#             sleep_till = (epoch_time - (epoch_time % 60)) + 60
#             '''how many seconds is that from now? then +- random connect buffer'''
#             sleep_seconds = (random.randint(-10, 10) + round((sleep_till - epoch_time), 2))
            sleep_seconds = pqrst
            logging.debug(sleep_seconds)
            time.sleep(sleep_seconds)
            
#             if (sleep_seconds > 10):        
#                 time.sleep(sleep_seconds)
#             else:
#                 time.sleep(60)
            
            if ((config_interval_counter >= config_interval) or (upload_interval_counter >= upload_interval)): 
               
                '''do we have an active northbound network connection'''
                interface, ip_address, netmask = network_ping_test(None)
                if ((interface != None) and (ip_address != None) and (netmask != None)):
                    
                    if (upload_interval_counter >= upload_interval):
                        
                        upload_interval_counter = 0
                        config_interval_counter = 0      
                        
                        '''get our current cpu temp'''
                        cpu_temp = get_cpu_temp()
                    
                        result_bsf = build_stat_file(ezs_id, interface, ip_address, cpu_temp, stream_cnt, srv_list)
                        
                        if result_bsf:
                            '''upload stat files'''
                            ftps_files("stat", ezs_id, cpu_sn, None)
                            
                        '''if wifi check commms to camera'''
                        if interface == "wlan0":    
                            network_ping_test("eth1")     
                    
                        '''upload any log or nmap files'''
                        if os.path.getsize("/home/pi/piotech/logs/cronlog") > 0:
                            build_log_file()    
                        result = ftps_files("log", ezs_id, cpu_sn, None)
                            
                    else:                        
                        if (config_interval_counter >= config_interval):
                            config_interval_counter = 0      
                            
                            '''stream heartbeat'''        
                            streams_running_count = check_stream_status(stream_cnt, srv_list) 
                        
                    ping_fail_counter = 0 
                    CURRENT_STATE = "CONFIG"
                    
                    if auth_sent == True:
                        auth_processed_counter -= 1
                        if auth_processed_counter == 0:
                            '''for now just reboot but could change state to auth'''
                            logging.warning("IDLE - Exceeded auth processed counter - no or corrupted config? - reboot")
                            ezs_reboot()
                           
                else:
                    logging.debug("IDLE - No Northbound Network Connection!!")
                    ping_fail_counter += 1
                    streams_running_count = check_stream_status(stream_cnt, srv_list)
                    
                    if ((ping_fail_counter >= max_fail_counter) and (streams_running_count == 0)):
                        logging.warning("IDLE - Exceeded ping failures with count = " + str(ping_fail_counter) + 
                                        " and no streams running - Reebooting!!")
                        ezs_reboot()
            else:
                config_interval_counter += 1
                logging.debug("config_interval_counter = " + str(upload_interval_counter))
                upload_interval_counter += 1
                logging.debug("upload_interval_counter = " + str(upload_interval_counter))    
                            
                '''stream heartbeat'''        
                streams_running_count = check_stream_status(stream_cnt, srv_list) 

        '''*****************************************************************''' 
        ''' CONFIG:                                                         '''
        '''                                                                 ''' 
        '''*****************************************************************''' 
        if CURRENT_STATE == "CONFIG":
            
            logging.debug("CURRENT_STATE = CONFIG")
            
            '''do we have an active network connection'''
            interface, ip_address, netmask = network_ping_test(None)
            if ((interface != None) and (ip_address != None) and (netmask != None)):

                file_list_sorted = retrieve_cfg_files(ezs_id, cpu_sn)
                if (len(file_list_sorted) > 0):           
                    for filename in file_list_sorted:
                                            
                        '''open this first/next file in the list and parse'''
                        try:
                            fp_cfg = open("../transfer/cfg/" + filename, "r")
                            data = fp_cfg.readlines()
                            struct_list = ["+EOF"]
                        except:
                            logging.warning("STATE=CONFIG - failed to open config file")
                            data = None;
                            
                        for line in data:
                            line = line.rstrip()
                            
                            '''All lines start with AT+'''
                            if "AT+" in line:
                                '''find the serial number'''
                                if "+DST=" in line:
                                    split_str = line.split("+DST=")
                                    if split_str[1] == ezs_id:
                                        logging.debug(split_str[1])
                                        logging.debug("its for us")
                                        
                                        '''set/reset some variables'''
                                        cfg_list = ["SRV", "ACT", "CMD#"]
                                        logging.debug(cfg_list)
                                        cmd_cmd_count = 0
                                    else:
                                        error_str = "Wrong DST"
                                        logging.warning(error_str)
                                        break
                                                                             
                                #'''find the service'''           
                                elif "+SRV=" in line:
                                    split_str = line.split("+SRV=")
    #                                 service_num = int(split_str[1])
                                    cmd_service = srv_list[int(split_str[1])]
                                    logging.debug("\nservice = " + cmd_service)
                                        
                                    '''remove from cfg_list'''
                                    cfg_list.remove("SRV")
                                    logging.debug(cfg_list)
                                    
                                #'''find the action'''    
                                elif "+ACT=" in line:
                                    split_str = line.split("+ACT=")
    #                                 action_num = int(split_str[1])
                                    cmd_action = act_list[int(split_str[1])]
                                    logging.debug("\naction = " + cmd_action)
                                        
                                    '''remove from cfg_list'''
                                    cfg_list.remove("ACT")
                                    logging.debug(cfg_list)                                
                                    
                                #'''find the command count (int)'''    
                                elif "+CMD#=" in line:
                                    split_str = line.split("+CMD#=") 
                                    cmd_cmd_count = int(split_str[1])
                                    tmp_counter = cmd_cmd_count
                                    logging.debug("\ncommand_count = " + split_str[1])
                                    
                                    '''append the number of commands to follow'''
                                    while tmp_counter > 0:
                                        cfg_list.append("CMD")
                                        tmp_counter -= 1
                                        
                                    '''remove from cfg_list'''
                                    cfg_list.remove("CMD#")
                                    logging.debug(cfg_list)  
                                    
                                #'''find the commands'''    
                                elif "+CMD=" in line:
                                    split_str = line.split("+CMD=")
                                    
                                    logging.debug("\ncommand = " + split_str[1])
                                    
                                    '''need better checking here but for now...'''
                                    if ((len(split_str[1]) > 5) and (cmd_action != "update")):
                                        decoded_str = de_crypto(cpu_sn, ezs_id, split_str[1])
                                    else:
                                        decoded_str = split_str[1]
                                        
                                    logging.debug("\ndecoded command = " + decoded_str)
                                    
                                    if cmd_action == "configure":   #1
                                        '''build the command pieces - going by order - should do KVP??'''
                                        if cmd_service == "ezstreamer":
                                            if cmd_cmd_count == 1: #eth0
                                                if (cfg_list.count("CMD") == 1):
                                                    #disable wlan0 here
                                                    #disable USB port here
                                                    pass
                                            elif cmd_cmd_count == 3: #wlan0 
                                                if (cfg_list.count("CMD") == 3):
                                                    #enable wlan0 here
                                                    #enable USB port here
                                                    pass
                                                if (cfg_list.count("CMD") == 2):
                                                    cmd_ssid = decoded_str
                                                    logging.debug("our cmd_ssid = " + cmd_ssid)
                                                if (cfg_list.count("CMD") == 1):
                                                    cmd_password = decoded_str
                                                    logging.debug("our cmd_password = " + cmd_password) 
                                            else:
                                                logging.warning("Invalid number of ezstreamer configure commands")                                            
                                        elif "stream" in cmd_service:
                                            if cmd_cmd_count == 7:
                                                if (cfg_list.count("CMD") == 7):
                                                    cmd_rtsp_link = decoded_str
                                                if (cfg_list.count("CMD") == 6):
                                                    cmd_silent_audio = decoded_str
                                                if (cfg_list.count("CMD") == 5):
                                                    cmd_min_br = decoded_str
                                                if (cfg_list.count("CMD") == 4):
                                                    cmd_min_fps = decoded_str    
                                                if (cfg_list.count("CMD") == 3):
                                                    cmd_max_runtime = str((int(decoded_str) * 1000000))                                                                                                
                                                if (cfg_list.count("CMD") == 2):
                                                    cmd_url_link = decoded_str
                                                if (cfg_list.count("CMD") == 1):
                                                    cmd_stream_key = decoded_str
                                            else:
                                                logging.warning("Invalid number of stream configure commands")
                                        else:
                                            logging.warning("Invalid service")                                    
                                        
#                                         '''remove from cfg_list'''
#                                         cfg_list.remove("CMD")
#                                         logging.debug(cfg_list)
                                        
                                    elif cmd_action == "restart":   #3
                                        if cmd_cmd_count != 0:
                                            logging.warning("Invalid number of restart configure commands")    
                                    elif cmd_action == "ssh":   #4
                                        if cmd_cmd_count == 1:
                                            cmd_ssh = decoded_str
                                        else:
                                            logging.warning("Invalid number of ssh configure commands")
                                    elif cmd_action == "update":   #5
                                        if cmd_cmd_count == 2:
                                            if (cfg_list.count("CMD") == 2):
                                                cmd_filename = decoded_str
                                                logging.debug("our cmd_filename = " + cmd_filename)
                                            if (cfg_list.count("CMD") == 1):
                                                cmd_file_sha256 = decoded_str
                                                logging.debug("our cmd_file_sha256 = " + cmd_file_sha256) 
                                        else:
                                            logging.warning("Invalid number of update configure commands")        
                                            
                                    elif cmd_action == "logging":   #6
                                        if cmd_cmd_count != 0:
                                            logging.warning("Invalid number of logging configure commands")
                                    elif cmd_action == "nmap":   #7
                                        if cmd_cmd_count != 0:
                                            logging.warning("Invalid number of nmap configure commands")
                                    elif cmd_action == "start":  #8
                                        if cmd_cmd_count != 0:
                                            logging.warning("Invalid number of start configure commands")                                         
                                    elif cmd_action == "stop":   #9
                                        if cmd_cmd_count != 0:
                                            logging.warning("Invalid number of stop configure commands")                                         
                                    else:
                                        logging.warning("Invalid action")
                                        
                                    '''remove from cfg_list'''
                                    if len(cfg_list) > 0:
                                        cfg_list.remove("CMD")
                                        logging.debug(cfg_list) 
                                    
                                #'''are we at the end of the command sequence'''
                                elif "+EOC" in line:
                                    logging.debug("@ EOC")
                                    
                                    if cmd_action == "configure":
                                        '''cfg_list should be empty here'''
                                        if len(cfg_list) == 0:
                                            if cmd_service == "ezstreamer":
                                                '''stop all streams and delete config files'''
                                                response = stream_control("stop_all", None)
                                                destroy_stream_config_files()
                                                '''init the number of streams to run'''
                                                stream_cnt = 0
                                                config_type = "full"                                                
                                                
                                                if cmd_cmd_count == 1:
#                                                     '''stop all streams and delete config files'''
#                                                     response = stream_control("stop_all", None)
#                                                     destroy_stream_config_files()
#                                                     '''init the number of streams to run'''
#                                                     stream_cnt = 0
                                                    
#                                                     '''eth0 - misconfigure wlan0'''
#                                                     result = configure_wlan0("Your_SSID", "Your_psk_012345")
                                                    '''disable wlan0'''
                                                    result = configure_wlan0(None, None)
                                                    '''delete any set routing'''
                                                    result = update_routes("delete", "eth0")
                                                    '''disable USB ports'''
                                                    result = hub_control("disable", "USB")
                                                    '''stop the isc-dhcp-server'''
                                                    result = dhcp_server_control("stop")
                                                    '''verify eth0 - network ping - metric 10'''
                                                    interface, ip_address, netmask = network_ping_test(None)
                                                    
                                                #'''wlan0 - configure wlan0'''
                                                elif cmd_cmd_count == 3:
#                                                     '''stop all streams and delete config files'''
#                                                     response = stream_control("stop_all", None)
#                                                     destroy_stream_config_files()
#                                                     '''init the number of streams to run'''
#                                                     stream_cnt = 0                                                
                                                    
                                                    '''enable USB ports'''
                                                    result = hub_control("enable", "USB")
                                                    result = configure_wlan0(cmd_ssid, cmd_password)
                                                    if result:
                                                        '''verify wlan0 - network ping force wlan0'''
                                                        interface, ip_address, netmask = network_ping_test("wlan0")
                                                        
                                                        '''delete any set routing'''
                                                        result = update_routes("delete", "eth0")
                                                        
                                                        '''route traffic from wlan0 to 10.56.173.2:80'''
                                                        result = update_routes("set", "wlan0")
                                                        logging.debug("update_routes result = " + str(result))

                                                    else:
                                                        logging.warning("EOC - Failed to set SSID and/or password")
                                                        
                                                    '''start/restart the isc-dhcp-server'''
                                                    result = dhcp_server_control("restart")
                                                else:
                                                    logging.warning("EOC - Invalid number of ezstreamer configure commands")
                                                     
                                            elif "stream" in cmd_service: 
                                                build_stream_config_files(cmd_service, cmd_rtsp_link, cmd_silent_audio,
                                                                          cmd_min_br, cmd_min_fps, cmd_max_runtime,
                                                                          cmd_url_link, cmd_stream_key)
                                                if config_type == "full":
                                                    stream_cnt += 1
            
                                            '''set/reset some variables'''
                                            cfg_list = ["SRV", "ACT", "CMD#"]
                                            logging.debug(cfg_list)
                                            cmd_cmd_count = 0
                                        else:
                                            logging.warning("EOC - Incomplete command structure")
                                    elif cmd_action == "restart" or cmd_action == "start" or cmd_action == "stop":
                                        if cmd_service == "ezstreamer":
                                            if cmd_action == "restart":
                                                ezs_reboot()
                                            elif cmd_action == "start":
                                                pass
                                            elif cmd_action == "stop":
                                                pass
                                            else:
                                                pass
                                        elif "stream" in cmd_service:
                                            response = stream_control(cmd_action, cmd_service)
                                            if response == 0:
                                                if cmd_action == "restart":
                                                    logging.warning("Failed to restart " + cmd_service)
                                                elif cmd_action == "start":
                                                    logging.warning("Failed to start " + cmd_service)
                                                elif cmd_action == "stop":
                                                    logging.warning("Failed to stop " + cmd_service)
                                                else:
                                                    pass   
                                        else:
                                            logging.warning("Invalid service for restart action") 
                                    elif cmd_action == "ssh":
                                        if "1" in cmd_ssh:
                                            ssh_control("enable")
                                        else:
                                            ssh_control(None)
                                    elif cmd_action == "update":
                                        if ((".txt" in cmd_filename) and (len(cmd_file_sha256) == 64)):
                                            response = process_update(ezs_id, cpu_sn, cmd_filename, cmd_file_sha256)
                                            if response == 1:
                                                time.sleep(3)
                                                ezs_reboot()  
                                        else:
                                            logging.warning("Invalid parameters for update action")
                                    elif cmd_action == "nmap":
                                        if cmd_service == "ezstreamer":
                                            '''get network snapshot'''
                                            nmap_control(ip_address, netmask)
                                        else:
                                            logging.warning("Invalid service for nmap action")                                                  
                                    else:
                                        pass
                                        
                                #'''are we at the end of the file'''
                                elif "+EOF" in line:
                                    config_type = None
                                    '''cude but if file complete clear the auth reboot'''
                                    auth_sent = False
                                    struct_list.remove("+EOF")
                                    logging.debug("@ EOF")
                                
                                #'''default'''    
                                else:
                                    logging.warning(line)        
                            else:
                                logging.warning("file corrupted!!")
                        
                        if fp_cfg:        
                            fp_cfg.close()
                        os.remove("../transfer/cfg/" + filename)
                        
                        if len(struct_list) != 0:
                            logging.warning("EOF - Incomplete command structure")
                            ezs_reboot()                        
            else:
                logging.debug("Config - No Network Connection!!")
            
            '''set our state'''
            CURRENT_STATE = "IDLE"
                
    logging.warning("All done!")
    
    # Exit:
    #----------------------------------------------------------
    #devcon.exit()
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if __name__ == '__main__':
    main()
