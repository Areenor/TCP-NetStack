NOTE: SOME OF THE CODE IS THE PROPERTY OF THE Vrije University of Amsterdam AND NOT PRODUCED BY ME

# TCP Netstack
ICMP protocol over IP, TCP protocol with the 3-way handshake connection establishmentand data transfer adhered to BSD socket semantics of the networking API calls.


## Code 
Here is a brief overview of the various files in this project 

  * anp_netdev.[ch] : implements the application privide network interface with 10.0.0.4 IP address 
  * anpwrapper.[ch] : shared library wrapper code that provides hooks for socket, connect, send, recv, and close calls. 
  * arp.[ch] : ARP protocol implementation. 
  * config.h : various configurations and variables used in the project.
  * debug.h : some basic debugging facility. Feel free to enhance it as you see fit. 
  * ethernet.h : Ethernet header definition  
  * icmp.[ch] : ICMP implementation (your milestone 2). 
  * init.[ch] : various initialization routines. 
  * ip.h : IP header definition 
  * ip rx and rx : IP tranmission and reception paths 
  * linklist.h : basic data structure implementation that you can use to keep track of various networking states (e.g., unacknowledged packets, open connections).
  * route.[ch] : a basic route cache implementation that can be used to find MAC address for a given IP (linked with the ARP implementation).
  * subuffer.[ch] : Linux kernel uses Socket Kernel Buffer (SKB) data strucutre to keep track of packets and data inside the kernel (http://vger.kernel.org/~davem/skb.html). This is our implementation of Socket Userspace Buffer (subuff). It is mostly used to build inplace packet headers.
  * systems_headers.h : a common include file with many commonly used headers. 
  * tap_netdev.[ch] : implementation for sending/receiving packets on the TAP device. It is pretty standard code. 
  * timer.[ch] : A very basic timer facility implementation that can be used to register a callback to do asynchronous processing. Mostly useful in timeout conditions. 
  * utilities.[ch] : various helper routines, printing, debugging, and checksum calculation.           
  
 ## How to build 
 
 ```bash
 cmake . 
 make 
 sudo make install  
 ```
 
 This will build and install the shared library. 
 
 ## Scripts 
 
 * sh-make-tun-dev.sh : make a new TUN/TAP device 
 * sh-disable-ipv6.sh : disable IPv6 support 
 * sh-setup-fwd.sh : setup packet forwarding rules from the TAP device to the outgoing interface. This script takes the NIC name which has connectivity to the outside world.  
 * sh-run-arpserver.sh : compiles a dummy main program that can be used to run the shared library to run the ARP functionality 
 * sh-hack-anp.sh : a wrapper library to preload the libanpnetstack and take over networking calls. 
 
 # Setup 
 After a clean reboot, run following scripts in the order 
  1. Make a TAP/TUN device 
  2. Disable IPv6 
  3. Setup packet forwarding rules
 
