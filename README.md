# Reverse-Port-Knocking-Shell

The project was undertaken as part of ECE 574 - Computer & Network Security

Project Details:
The project is implemented in C++ using pcap, curl and curlpp libraries. 

1. Knocker - 
Reads the config file for port knock sequence, creates a socket and sends empty packets to ports in the port sequence order.

2. Backdoor - 
Reads the config file for port sequence, sniffs the ports for incoming packets, stores the port address and source ip of incoming udp packets and compares the port sequence whenever a new packet is received. Different port sequence list is maintained for each source ip. When a correct knock is received, a call to the url is made using curl library and the response is executed using system function call.
