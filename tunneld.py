#!/usr/bin/env python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer 
import socket, select
import cgi
import argparse
import base64
from Crypto.Cipher import AES
import ssl
from config import aes_share
from config import tunneld_config

class ProxyRequestHandler(BaseHTTPRequestHandler):

    sockets = {}
    BUFFER = 1024 * 50 
    SOCKET_TIMEOUT = 50
    # the block size for the cipher object; must be 16, 24, or 32 for AES
    BLOCK_SIZE = 32
    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
    # used to ensure that your value is always a multiple of BLOCK_SIZE
    PADDING = '{'
    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    
    # one-liners to encrypt/encode and decrypt/decode a string
    # encrypt with AES, encode with base64
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    
    
    # secret key, change this if you want to be unique
    
    # create a cipher object using the random secret
    cipher = AES.new(aes_share.secret)    

    def _get_connection_id(self):
        return self.path.split('/')[-1]

    def _get_socket(self):
        """get the socket which connects to the target address for this connection"""
        id = self._get_connection_id()
        return self.sockets.get(id, None)

    def _close_socket(self):
        """ close the current socket"""
        id = self._get_connection_id()
        s = self.sockets[id]
        if s:
            s.close()
            del self.sockets[id]

    def do_GET(self):
        """GET: Read data from TargetAddress and return to client through http response"""
        # the block size for the cipher object; must be 16, 24, or 32 for AES
        BLOCK_SIZE = 32
        # the character used for padding--with a block cipher such as AES, the value
        # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
        # used to ensure that your value is always a multiple of BLOCK_SIZE
        PADDING = '{'
        # one-liner to sufficiently pad the text to be encrypted
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
        
        # one-liners to encrypt/encode and decrypt/decode a string
        # encrypt with AES, encode with base64
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))        
        s = self._get_socket()
        if s:
            # check if the socket is ready to be read
            to_reads, to_writes, in_errors = select.select([s], [], [], 5)
            if len(to_reads) > 0: 
                to_read_socket = to_reads[0]
                try:
                    print "Getting data from target address" 
                    data = to_read_socket.recv(self.BUFFER)
                    #print data
                    self.send_response(200)
                    self.end_headers()
                    if data:
                        self.wfile.write(EncodeAES(self.cipher,data))
                except socket.error as ex:
                    print 'Error getting data from target socket: %s' % ex  
                    self.send_response(503)
                    self.end_headers()
            else: 
                print 'No content available from socket'
                self.send_response(204) # no content had be retrieved
                self.end_headers()
        else:
            print 'Connection With ID %s has not been established' % self._get_connection_id()
            self.send_response(400)
            self.end_headers()


    def do_POST(self):
        """POST: Create TCP Connection to the TargetAddress"""
        id = self._get_connection_id() 
        print 'Initializing connection with ID %s' % id
        length = int(self.headers.getheader('content-length'))
        req_data = self.rfile.read(length)
        params = cgi.parse_qs(req_data, keep_blank_values=1) 
        target_host = params['host'][0]
        target_port = int(params['port'][0])

        print 'Connecting to target address: %s % s' % (target_host, target_port)
        # open socket connection to remote server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # use non-blocking socket
        s.setblocking(0)
        s.connect_ex((target_host, target_port))

        #save socket reference
        self.sockets[id] = s
        try: 
            self.send_response(200)
            self.end_headers()
        except socket.error, e:
            print e

    def do_PUT(self):
        """Read data from HTTP Request and send to TargetAddress"""
        DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(self.PADDING)
        id = self._get_connection_id()
        s = self.sockets[id]
        if not s:
            print "Connection with id %s doesn't exist" % id
            self.send_response(400)
            self.end_headers()
            return
        length = int(self.headers.getheader('content-length'))
        data = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)['data'][0] 

        # check if the socket is ready to write
        to_reads, to_writes, in_errors = select.select([], [s], [], 5)
        if len(to_writes) > 0: 
            #print 'TEST:' + self.DecodeAES(self.cipher,data)
            #print 'TEST:' + data
            #print 'Sending data .... %s' % data
            to_write_socket = to_writes[0]
            try:
                #print "TEST: " + data
	#	print DecodeAES(self.cipher,data)
                to_write_socket.sendall(DecodeAES(self.cipher,data))
                self.send_response(200)
            except socket.error as ex:
                print 'Error sending data from target socket: %s' % ex  
                self.send_response(503)
        else:
            print 'Socket is not ready to write'
            self.send_response(504)
        self.end_headers()

    def do_DELETE(self): 
        self._close_socket()
        self.send_response(200)
        self.end_headers()

def run_server(port, server_class=HTTPServer, handler_class=ProxyRequestHandler): 
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile=tunneld_config.cert_file, server_side=True,ssl_version=ssl.PROTOCOL_TLSv1)
    print httpd.socket
    httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start Tunnel Server")
    parser.add_argument("-p", default=9999, dest='port', help='Specify port number server will listen to', type=int)
    args = parser.parse_args()
    run_server(args.port)
