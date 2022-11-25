# Reverse Traceroute
This repository contains reference implementations for reverse traceroute client and server applications.  

Altough the protocol itself is able to support both IPv4 and IPv6 implementations,
this work currently only runs on IPv4.

## The problem we want to solve
Traceroute provides information on the forward path towards a target.
As such, it is popular for troubleshooting problems on the forward path.
Should a problem arise on the reverse path traceroute's output offers no help
and may even be misleading.  

Thats why we developed reverse traceroute.
Reverse traceroute allows you to determine the reverse path from a target host,
which runs our server program, back to you,
enabling you to detect and (hopefully) troubleshoot said issues.

## Design goals
Reverse traceroute was built in accordance with the following principles:

1. No direct control over the remote host ✅  
    Access to the target host is not required. The target merely has to run our server.
2. Safe to use ✅  
    Reverse traceroute must not introduce possible attack vectors inside a network.
3. Deployable in todays Internet ✅  
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
    Reverse traceroute behaves just like regular traceroute. You can send UDP, TCP and ICMP probes
    and expect both node address and Round-Trip-Time as a measurement.

## Client
The client application supports both single- and multipath discovery.  
When run in the singlepath mode a fixed flow identifier has to be specified, which
determines the path that the traceroute probes will illuminate.  
When run in the multipath mode, a variation of the [Diamond Miner](https://github.com/dioptra-io/diamond-miner)
algorithm ensures that all nodes for a hop will be detected with a certainty specified by the user.

Both modes of operation can be used to in the forward and, since we are talking about reverse traceroute,
in the **reverse** direction.

As the client renders the discovered paths, you need the graphviz binary accessible through your
`PATH` variable.

### Examples
To discover multiple paths towards a destination with TCP, use the following command:
```
augsburg-traceroute forward tcp multipath <target>
```

To discover only a single reverse path identified by flow 1234 with UDP back from a target:
```
augsburg-traceroute reverse udp singlepath --flow 1234 <target>
```

To discover both reverse and forward paths with TCP and submit the results to our measurement study:
```
augsburg-traceroute --transmit two-way tcp multipath <target>
```

The client provides a few more fine-grained controls to influence the probing behaviour.  
Run `augsburg-traceroute -h` to learn more.

## Server
The server application is written as an [eBPF](https://ebpf.io/what-is-ebpf/) program.
In order to parse reverse traceroute requests and responses before they
are processed by the kernel, it is attached to a traffic control ingress hook.

As the application makes use of recent eBPF features such as timers,
at least a linux kernel version of `5.15.0` is required.

You can specify both the size of the session buffer and the timeout value,
after which unanswered sessions are dropped.  
The interface index on which the server will process reverse traceroute traffic
is a mandatory argument.

```
augsburg-traceroute-server [-n MAX_SESSIONS] [-t TIMEOUT_NS] ifindex
```

### Examples
To run the server on the interface with index 2, with at most 50.000 sessions and
and a session timeout of 5 seconds:

```
augsburg-traceroute-server -n 50000 -t 5000000000 2
```

## Building the software
In the `server/` directory run:
```
bash build_docker.sh
```
The executable will be built in a docker container that includes
the needed dependencies.

## Measurement study
We are trying to collect data about traceroute paths for our measurement study.
If you want to participate, you can use the `--transmit` switch in the client
to transmit your data to our server.  

Please be aware that the data includes hostnames by default.
If you do not want to transmit resolved hostnames as part of the trace
you can use the `--no-resolve` client switch.

## Running a public server
Reverse traceroute was designed as a distributed service.
Hence it lives from the people who decide to host publicly available server endpoints.

Should you decide to host such a reverse traceroute server,
then please let us know so that we can add your server to the list of endpoints,
which are maintained inside the `ENDPOINTS` file.

## Future work
* Implement IPv6 support for client and server
* Introduce alias resolution to match nodes on both the forward and reverse path

## Disclaimer
Both the client and the server are subject to change, as they are still early in development.
As such, you may encounter bugs.

## Resources
Project website: https://net.hs-augsburg.de/en/project/reverse-traceroute/  
Protocol draft: https://datatracker.ietf.org/doc/html/draft-heiwin-intarea-reverse-traceroute  
Talk at DENOG: https://youtu.be/Y7NtqLEtgjU

## Contact
Valentin Heinrich <valentin.heinrich@hs-augsburg.de\>  
Rolf Winter <rolf.winter@hs-augsburg.de\>
