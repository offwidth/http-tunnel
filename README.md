HTTPS TUNNEL AES
==========

This was built to create an https tunnel that puts a layer of AES in between.  The easiest way to set it up is to use the wizard.
The wizard will build the standalone exe to deploy.

On your metasploit server or wherever your server has its exposed outside run the tunneld.py 

ex:
tunneld.py -p 9000


The wizard will create an exe with 2 payloads.  Meterpreter reverse http or download and execute.

I'm debating still using https payload, though it already wraps everything in ssl.

Download and execute lets you use your own custom exe.   If build you own exe follow these general rules:

The payload needs to talk to localhost(127.0.0.1) on the assigned port in the wizard
ex:
127.0.0.1:8000 
The wizard refers to this as the listen port.

The remote address is where your tunneld resides.
ex:
www.iamsomehwere.com:8081

The wizard asks where the multi address because its expecting a metasploit listener but this could be a nc listner if one wants
One rule is that the local listner and the remote port should be unique.
Another rule is that the remote address (where the multi hanlder is) should not be refered to by localhost(127.0.0.1) but should be ip address or hostname.  It gets confused with a loopback.

The metasploit handler does not need to be exposed to the internet since the traffic is being foward on.  On the tunnel does.  The tunneld can also can foward to mutiple hosts, so you don't need a tunneld for every handler.

Future release will use a client server cert but for now it just generates a self signed cert and then an AES shared key


