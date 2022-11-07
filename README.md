# Reverse Traceroute

This repository contains reference implementations for reverse traceroute client and server applications.  
  
These tools aim to fix the shortcomings of a classic traceroute, which is able to illuminate the forward path.
Due to the Internet's asymmetric nature, meaning that forward and reverse paths often differ,
the output of classic traceroute is of limited for problems arising only on the reverse path.

## Protocol
Reverse traceroute makes use of newly defined ICMP codes for the Echo Request/Response messages.
Our measurements have shown that by reusing the existing ICMP Echo message types with a new code,
the packets are able to traverse the Internet unfiltered in the majority of cases.

For each hop the client wishes to discover, it sends a reverse traceroute request message to the server.
The server evaluates the response and notifies the client if an invalid configuration was specified.  
Otherwise the server creates a new session associated with said request and issues a probe back towards
the requester.
When receiving a probe response the server computes the Round-Trip-Time (RTT) elapsed between
issuing the probe and receiving the corresponding response.
The address of the responding node and the RTT are then delivered back to the requestor.

For more details on the inner workings of the reverse traceroute protocol check out the
[internet draft](https://datatracker.ietf.org/doc/draft-heiwin-intarea-reverse-traceroute/).

## Measurement study
Our aim is to use reverse traceroute to study the characteristics of the Internet.
If you want to support us, you can use the client application to transmit your measurement
data to our server. Have a look at the examples for further information.

## Client
The client application is able to traverse multiple path to- and from a target.  
It uses a variation of the Diamond Miner [1]() algorithm for detection of multiple paths.
In order to discover the reverse path, the destination node has to run the reverse traceroute server.

You need an installation of graphviz to run the client application, as it relies on graphviz
to render the trace as a graph.

### Examples
To discover only paths towards a destination with TCP, use the following command:
```
augsburg-traceroute -f -T target
```

To discover only reverse path with UDP from a destination, which runs the reverse traceroute server:
```
augsburg-traceroute -r -U target
```

To discover both reverse and forward paths with TCP and submit the results to our measurement study:
```
augsburg-traceroute -rf -T -t target
```

## Server
The server application is written as an eBPF program.
It parses packets before they reach the Linux kernels TCP/IP Stack, which allows it to handle
ICMP packet before they are processed by the kernel.

You can specify both the size of the session buffer and the timeout value,
after which to drop sessions that have not seen a suitable probe response.

```
augsburg-traceroute [-n MAX_SESSIONS] [-t TIMEOUT_NS] ifindex
```

In order to run the reverse traceroute server a kernel version of at least 5.15.0 is required.

## Building the software
To build both the client and server, run ```make``` in the project's root directory.  

For building the client, you need the poetry tool.

For building the server, the following dependencies are required:
* clang-14
* libelf-dev
* linux-headers-generic

## Disclaimer
Both the client and the server are subject to change, as they are still early in development.
As such, you may encounter bugs.
