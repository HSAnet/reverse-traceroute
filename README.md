# Reverse Traceroute
Reverse traceroute is an extension to ICMP, enabling hosts to request traceroute measurements back to themselves from a remote target.  
Additionally, the client may request indirect traces from a remote endpoint towards an arbitrary target if the remote endpoint allows it.  
For detailed information about reverse traceroute and its concepts, have a look at the [resources](#resources).

This repository contains reference implementations for reverse traceroute client and server applications.  
Both the protocol and tools are able to support IPv4 and IPv6.

## The Problem we want to solve
Traceroute provides information on the forward path towards a target.
As such, it is popular for troubleshooting problems on the forward path.
Should a problem arise on the reverse path traceroute's output offers no help
and may even be misleading.  

That's why we developed reverse traceroute.
Reverse traceroute allows you to determine the reverse path from a target host,
which runs our server program, back to you,
enabling you to detect and (hopefully) troubleshoot said issues.

## Design Goals
Reverse traceroute was built in accordance with the following principles:

1. No direct control over the remote host ✅  
    Access to the target host is not required. The target merely has to run our server.
2. Safe to use ✅  
    Reverse traceroute must not introduce possible attack vectors inside a network.
3. Deployable in today's Internet ✅  
    The messages sent by reverse traceroute should be able to traverse the Internet unaltered.
4. Policable by network operators ✅  
    Network operators who do not want reverse traceroute traffic inside their administrative domain
    can easily enforce such restrictions.
5. Awareness of load balancing ✅  
    Reverse traceroute knows how to keep packets on a single path.
6. No hackery (IP Spoofing / IP Options) ✅  
    We refrain from using unorthodox means and practices, such as IP spoofing.
7. No changes to routers required ✅  
    The chances of deploying reverse traceroute in the wild increase when leaving routers untouched.
8. Mimic classic traceroute ✅  
    Reverse traceroute behaves just like regular traceroute. You can send UDP, TCP and ICMP probes and expect both node address and Round-Trip-Time as a measurement.

## Installation
We provide Debian packages for Ubuntu 22.04 LTS for both client and server.  
First add the repository's signing key to your trusted keyrings:
```
curl https://deb.net.hs-augsburg.de/signing_key.gpg -o /etc/apt/trusted.gpg.d/deb.net.hs-augsburg.de.gpg
```

Then the repository itself can be added by appending the following lines to your `/etc/apt/sources.list`:
```
# Augsburg Traceroute
deb [ signed-by=/etc/apt/trusted.gpg.d/deb.net.hs-augsburg.de.gpg ] http://deb.net.hs-augsburg.de jammy/
```

Finally, the packages can be installed with the following command:
```
sudo apt update
sudo apt install augsburg-traceroute-client augsburg-traceroute-server
```

## Running as a service
To easily integrate the server into the system we provide systemd-service templates
with the Debian package. You can enable and start the service on an interface with the following command:

```
sudo systemctl enable --now augsburg-traceroute-server-v4@<ifname>
sudo systemctl enable --now augsburg-traceroute-server-v6@<ifname>
```

To change the arguments passed to the server you can edit the service:
```
sudo systemctl edit --full augsburg-traceroute-server-v4@<ifname>
sudo systemctl edit --full augsburg-traceroute-server-v6@<ifname>
```

## Indirect Tracing
The protocol supports an extension that allows clients to request traceroute measurements to arbitrary targets.  
**This feature is disabled by default** and can be controlled on the server-side:  
You can restrict the networks from which such indirect tracing requests can be made by editing relevant configuration files and explicitly enabling indirect traces for the server.  
For information on how to do this you can consult the augsburg-traceroute-server manpage.

## Measurement Study
We are trying to collect data about traceroute paths for our measurement study.
If you want to participate, you can use the `--transmit` switch in the client
to transmit your data to our server.  

Please be aware that the data includes hostnames by default.
If you do not want to transmit resolved hostnames as part of the trace
you can use the `--no-resolve` client switch.

## Running a public Endpoint
Reverse traceroute was designed as a distributed service.
Hence, it lives from the people who decide to host publicly available server endpoints.

Should you decide to host such a reverse traceroute server,
then please let us know so that we can add your server to the list of endpoints,
which are maintained inside the `ENDPOINTS` file.

## Future Work
* Optimize the client
* Add unit tests to client and server

## Disclaimer
Both the client and the server are subject to change, as they are still early in development.
As such, you may encounter bugs.  
Reverse traceroute employs code points that are not yet assigned by IANA,
namely _ICMP Echo Requests/Responses_ with a new code. 

## Resources
Project website: https://net.hs-augsburg.de/en/project/reverse-traceroute/  
Protocol draft: https://datatracker.ietf.org/doc/html/draft-heiwin-intarea-reverse-traceroute  
Talk at DENOG: https://youtu.be/Y7NtqLEtgjU

## Contact
Valentin Heinrich <valentin.heinrich@hs-augsburg.de\>  
Rolf Winter <rolf.winter@hs-augsburg.de\>
