#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

int main(int argc, char* argv[])
{
	char* config_file;
	char* target_ip;

	// 1. Read command-line args
	if (argc <= 1 || argv[1] == NULL || argv[2] == NULL)
	{
		printf("Incorrect parameters\n");
		return 1;
	}

	config_file = argv[1];
	target_ip = argv[2];

	printf("Config file = %s, Target ip = %s\n", config_file, target_ip);
		
	// 2. Read config file
	FILE * file;
	file = fopen(config_file, "r");

	if (file == NULL)
	{
		printf("Config file not found\n");
		return -1;
	}

	// 3. Send packets with port number 
	// Create socket
	int socket_fd;
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	if (socket_fd<0)
	{
		printf("error in socket\n");
		return -1;
	}

	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(target_ip);

	// Parse input file for knock sequence
	char buffer[10];
	while (fgets(buffer, 10, file) != NULL)
	{
		// Send the knocks
		server_address.sin_port = htons(atoi(buffer));
		sendto(socket_fd, "", 1, 0, (struct sockaddr*)&server_address, sizeof(server_address));
	}

	close(socket_fd);

	return 0;
}