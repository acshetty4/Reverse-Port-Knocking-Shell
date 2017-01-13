#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
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
#include <sys/types.h>
#include <time.h>
#include <fstream>
#include <pcap/pcap.h>
#include <map>
#include <vector>
#include <algorithm> // for find
#include <sstream> 
#include <iostream>
using namespace std;

#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
using namespace curlpp::options;

char* config_file;
char* url;

int udp=0, others=0,total=0;

int knock_seq_length = 0;

int* knock_seq = NULL;
struct iphdr *iph = NULL;
struct tcphdr *tcph = NULL;
struct udphdr *udph = NULL;
struct sockaddr_in source;

struct ip_portseq
{
	bool bValid;
	std::string sourceIP;
	std::vector<unsigned int> port_seq;
};

struct ip_portseq ip_port[1024]; // Lets have 1024 different ip possible
	
void process_udp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
	char* sourceIP;
	unsigned int port;
	
	// Extract source ip and dest port from udp packet
	iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	sourceIP = inet_ntoa(source.sin_addr);
	port = ntohs(udph->dest);

	printf("\nUDP Packet\n");
	printf("IP source address: %s\n", sourceIP);
	printf("Destination Port : %u\n", port);
	
	// Insert the port-ip pair into a list
	int current_element;
	for(int i = 0; i < 1024; i++)
	{
		if(ip_port[i].bValid == true)
		{
			if(strcmp(ip_port[i].sourceIP.c_str(), sourceIP) == 0)
			{
				// IP exists in list
				ip_port[i].port_seq.push_back(port);
				current_element = i;
				//printf("Pushing %u into %s's list\n", port, ip_port[i].sourceIP.c_str());
				break;
			}
		}
		else
		{
			// New source IP.. Insert into list
			ip_port[i].bValid = true;
			ip_port[i].sourceIP = sourceIP;
			ip_port[i].port_seq.push_back(port);
			current_element = i;
			//printf("New IP %s Port = %u", ip_port[i].sourceIP.c_str(), port);
			break;
		}
	}
	
	std::vector<unsigned int>::iterator it_start = ip_port[current_element].port_seq.begin();
	std::vector<unsigned int>::iterator it_end = ip_port[current_element].port_seq.end();
	cout<<"Contents of vector:\n";
	for(std::vector<unsigned int>::iterator trace_it = it_start; trace_it!=it_end; trace_it++)
	{
		cout<<*trace_it<<" ";
	}
	cout<<endl;
	
	// Compare sequence
	std::vector<unsigned int>::iterator it;
	int good_knock = 0;
	for(int knock_ctr=0; knock_ctr < knock_seq_length && it_start!=it_end; knock_ctr++)
	{
		it = find(it_start, it_end, knock_seq[knock_ctr]); // Find the knock seq in the stored port sequence
		if (it != ip_port[current_element].port_seq.end())
		{
			good_knock++;
			it_start++;
			//it_end--;
		}
		else
		{
			cout<<"No match found\n";
			if (good_knock != knock_ctr + 1)
				ip_port[current_element].port_seq.clear(); // pop_back();
		}
	}

	if(good_knock==knock_seq_length)
	{
		printf("Knocked\n");
		ip_port[current_element].port_seq.clear();
		
		try
		{
			curlpp::Cleanup myCleanup;

			std::ostringstream os;
			os << curlpp::options::Url(std::string(url));

			string response_str = os.str();
			printf("String = %s\n", response_str.c_str());
			
			if (response_str.c_str() != NULL)
				system(response_str.c_str());
		}
		catch (exception e)
		{
			printf("Invalid url\n");
		}
	}
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
     
    //Get the IP Header part of this packet , excluding the ethernet header
    iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 17: //UDP Protocol
            ++udp;
            process_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            break;
    }
}

int main(int argc, char* argv[])
{
	// 1. Read cmd-line args
	if (argc <= 1 || argv[1] == NULL || argv[2] == NULL)
	{
		printf("Incorrect parameters");
		return 1;
	}
	
	config_file = argv[1];
	url = argv[2];
	
	// 2. Read config file
	FILE * pFile;
	pFile = fopen(config_file, "r");

	if (pFile == NULL)
	{
		printf("Config file not found\n");
		return 1;
	}

	// 3. Read and store knock sequence
	std::ifstream myfile(config_file);
	std::string line;
	
	while (std::getline(myfile, line))
		++knock_seq_length;

	knock_seq = new int[knock_seq_length];
	
	char strBuffer[10];
	int i = 0;
	
	char** knock_buffer = new char*[knock_seq_length];
	while (fgets(strBuffer, 10, pFile) != NULL)
	{
		knock_seq[i] = atoi(strBuffer);
		knock_buffer[i] = new char[6];
		sprintf(knock_buffer[i], "%d", knock_seq[i]);
		//printf("knock[%d] = %d", i, knock_seq[i]);
		i++;
	}
	cout<<endl;
	
	// initialize struct
	for(int i = 0; i < 1024; i++)
	{
		ip_port[i].bValid = false;
	}
	
	// Create filter expression
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed
	struct bpf_program fp;		/* The compiled filter expression */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	
	char* filter_exp = new char[knock_seq_length*20];	/* The filter expression */
	
	strcpy(filter_exp, "port ");
	strcat(filter_exp, knock_buffer[0]);
	
	for (int i = 1; i < knock_seq_length; i++)
	{
		strcat(filter_exp, " or port ");
		strcat(filter_exp, knock_buffer[i]);
	}
	cout << filter_exp<<endl;
	
	//First get the list of available devices
	char errbuf[100], *devname, devs[100][100];
	int count = 1, n;

	printf("Finding available devices ...\n ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
	     printf("Error finding devices : %s" , errbuf);
	     exit(1);
	}
	printf("Done\n");
			           
	//Print the available devices
	printf("Available Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
	      //printf("%d. %s - %s\n" , count , device->name , device->description);
	      if(device->name != NULL)
	      {
			printf("%d. %s\n" , count , device->name);
	        strcpy(devs[count] , device->name);
	      }
	      count++;
	}
	
	for(int i = 1; i < count; i++)
	{
		//Open the device for sniffing
    		devname = devs[i];

		printf("Opening device %s for sniffing ... " , devname);
		if(strcmp(devname, "nflog") != 0)// || strcmp(devname, "eth1") == 0 || strcmp(devname, "any") == 0 )
    		handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
     
		if (handle == NULL) 
		{
        	fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        	exit(1);
    	}
		
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
		{
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(1);
		}
		else
		{
			printf("Compile successful..");
		}
		
		if (pcap_setfilter(handle, &fp) == -1) 
		{
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(1);
		}
		else
		{
			printf("Set filter successful..");
		} 
    	printf("Done\n");
     }

	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , NULL);

	return 0;
}