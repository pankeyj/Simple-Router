#include <sys/socket.h>  
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/types.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include "help.h"
// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data
#define ICMP_PROTO 1
/************************************************** 
 * Including this file causes redefinition of
 * of structs so I will create arp structs manually
 **************************************************/
//#include <linux/if_arp.h>

/*Global ICMP Header */
struct icmpHdr *icmphdr, *echoReqIcmp;
/*Global IP Header */
struct ipHdr *iphdr, *echoReqIp;
/* Struct to find ip addresses */
struct ifreq if_mac;
/*Global Ethernet Headers */
struct ether_header* ether;
struct ether_header* etherRepl;
/* Global Arp Headers */
struct arpReq* arpReq;
struct arphdr* arpRepl;
/* Recv address is used each time send is called 
 * Unique to each interface */
struct sockaddr_ll recvaddr[4];

void buildArpResponse();
unsigned char* sendArpRequest(unsigned char tmp[4], int id);
void recvArpResponse(char buf[1500], int id);
void arpRequest(char recvBuf[1500], int id);
void recvIP(char recvBuf[1500], int id);
void myRecv(int id);

/* One socket for each interface at most four */
int packet_socket[4];
/* Source Mac Addresses on each interface */
u_int8_t src_mac[4][6];
/* Destination Mac Addresses for each interface */
unsigned char dest_mac[4][6];
/* Ip addresses on each interface */
unsigned char src_ip[4][4];
/* One thread to listen on each interface */
pthread_t child[4];

int main(){
	int k;
	// Zero out the mac address until discovered
	for(k = 0; k < 4; k++)
		memset(dest_mac[k], '\0', 6);

  //get list of interfaces (actually addresses)
	char buf[1500];
	struct ifaddrs *ifaddr, *tmp;
	if(getifaddrs(&ifaddr)==-1){
		perror("getifaddrs");
		return 1;
	}
	int id = 0;
	//have the list, loop over the list
	for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
	//Check if this is a packet address, there will be one per
	//interface.  There are IPv4 and IPv6 as well, but we don't care
	//about those for the purpose of enumerating interfaces. We can
	//use the AF_INET addresses in this list for example to get a list
	//of our own IP addresses
	/****************************************
	* Looking for mac address
	****************************************/
		if(strncmp(&(tmp->ifa_name[0]),"lo",2))
		{
		
                
			if(tmp->ifa_addr->sa_family==AF_PACKET){
				printf("Interface: %s\n",tmp->ifa_name);
			
				
				struct sockaddr_ll *s = (struct sockaddr_ll *) tmp->ifa_addr;
				memcpy(&recvaddr[id], tmp->ifa_addr, sizeof(tmp->ifa_addr));
				int i;
				int len = 0;
				for(i = 0; i < 6; i++)
					printf("%02X%s",s->sll_addr[i],i < 5 ? ":":"\n");
				printf("INterface Index %d\n", s->sll_ifindex);	
	

				for(i = 0; i < 6; i++)
					src_mac[id][i] = s->sll_addr[i];
		
				packet_socket[id] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
				printf("Current Id %d\n", id);	
				
				if(bind(packet_socket[id], tmp->ifa_addr ,sizeof(struct sockaddr_ll)) == -1)
				{
					perror("bind");
				}

				printf("Creating Socket on interface %s\n",tmp->ifa_name);
	
				// Find the ip address of this interface. Save
				// this value to the global variable src_ip[id]
				// id is the index of this interface
				struct ifreq ifr;
				ifr.ifr_addr.sa_family = AF_PACKET;
				strncpy(ifr.ifr_name, tmp->ifa_name,IFNAMSIZ-1);
				ioctl(packet_socket[id], SIOCGIFADDR, &ifr);
				struct sockaddr_in *sa = (struct sockaddr_in*)&ifr.ifr_addr;
				memcpy(src_ip[id],&sa->sin_addr.s_addr, sizeof(src_ip[id]));
				printf("IP:%2x.%2x.%2x.%2x \n ",src_ip[id][0],src_ip[id][1],src_ip[id][2],src_ip[id][3]);
	

				// For ever interface create a thread that listens on it
				pthread_create(&child[id],NULL, myRecv, id);
				id++;
				
				if(packet_socket<0)
				{
					perror("socket");
					return 1;
				}
			}
		}	
	}
	freeifaddrs(ifaddr);
	pthread_join(child[0], NULL);
	pthread_join(child[1], NULL);
	pthread_join(child[2], NULL);
	return 0;
}

void myRecv(int id)
{	
	char buf[1500]; 
	printf("Ready to recieve now on id:%d\n",id);
	while(1)
	{
		int recvaddrlen=sizeof(struct sockaddr_ll);
		//we can use recv, since the addresses are in the packet, but we
		//use recvfrom because it gives us an easy way to determine if
		//this packet is incoming or outgoing (when using ETH_P_ALL, we
		//see packets in both directions. Only outgoing can be seen when
		//using a packet socket with some specific protocol)
		memset((void*)buf, '0', sizeof(buf));
		printf("Interface ID %d waiting to recieve\n", id);
		int n = recvfrom(packet_socket[id], buf, 1500,0,(struct sockaddr*)&recvaddr[id], &recvaddrlen);
		//ignore outgoing packets (we can't disable some from being sent
		//by the OS automatically, for example ICMP port unreachable
		//messages, so we will just ignore them here)
		if(recvaddr[id].sll_pkttype==PACKET_OUTGOING)
		continue;
		//start processing all other
		printf("Got a %d byte packet\n", n);
		//what else to do is up to you, you can send packets with send,
		//just like we used for TCP sockets (or you can use sendto, but it
		//is not necessary, since the headers, including all addresses,
		//need to be in the buffer you are sending)
   	
		
		/* Contains physical addresses and type of message */
		int offset = 0;	
		ether = (struct ether_header*) buf;
		offset += sizeof(struct ether_header);
		arpReq = (struct arpReq *) (buf + offset);
		
		// Determine which type of packet was received.
		// Take appropriate action for each.
		if((htons(ether->ether_type)) == ETHERTYPE_ARP)
		{
			printf("Recieved an arp packet on interface %d\n", id);
			if(arpReq->ar_op == htons(ARPOP_REQUEST))
			{
				printf("Recieved arp request\n");
				buildArpResponse(id);
			}
			else
			{
				printf("Recieved arp response on interface %d outside function call\n", id);
				recvArpResponse(buf, id);		
	}
		}
		else if((htons(ether->ether_type)) == ETHERTYPE_IP)
		{
			printf("Recieved an ip packet on interface %d\n", id);
			recvIP(buf, id);
		}
		else
		{
			printf("Recieved another type of packet on interface %d\n", id);
		}
	}
}
/****************************************************
 * @param id - Specifies which interface the
 * 	arp response was received on.
 * This function is called when an arp request is
 * received. The interface responds by swapping
 * the destination mac address with the destination. Next it
 * fills in the source mac with its own address. Finally
 * it changes the arp operation type to Reply
 *****************************************************/
void buildArpResponse(int id)
{
	char buf[42];
	struct ether_arp *arpEnd;
	int result, offset;
	etherRepl = (struct ether_header *) buf;
	arpRepl = (struct arphdr *) buf + (sizeof(struct ether_header));
	arpEnd = (struct ether_arp *) buf + ((sizeof(struct ether_header)) + (sizeof(struct arphdr)));	
	arpRepl->ar_hrd = htons(ARPHRD_ETHER);
	arpRepl->ar_pro = htons(ETH_P_IP);
	arpRepl->ar_hln = 0x06;
	arpRepl->ar_pln = 0x04;
	arpRepl->ar_op = htons(ARPOP_REPLY);

	unsigned char tmpha[6];
	unsigned char tmppa[4];

	memcpy(arpEnd->arp_spa, arpReq->ar_tip, 4);
	memcpy(arpEnd->arp_sha, src_mac[id], 6);
	memcpy(arpEnd->arp_tha, ether->ether_shost, 6);
	memcpy(arpEnd->arp_tpa, arpReq->ar_sip, 4);
	int i;
	for(i = 0; i < 6; i++ )
	{
		etherRepl->ether_dhost[i] = ether->ether_shost[i];
		etherRepl->ether_shost[i] = src_mac[id][i];	
	}
	etherRepl->ether_type = ether->ether_type;
	offset = 0;

	// Copies the values from the structures into the buffer
	memcpy((void*)buf, (void*) etherRepl, sizeof(struct ether_header));
	offset += sizeof(struct ether_header);
	memcpy((void*)(buf + offset), (void*) arpRepl, sizeof(struct arphdr));	
	offset += sizeof(struct arphdr);
	memcpy((void*)buf + offset, (void*)arpEnd, sizeof(struct ether_arp));
	// Sends the response
	result = sendto(packet_socket[id], buf, sizeof(buf), 0,
		(struct sockaddr*) &recvaddr[id], sizeof(recvaddr[id]));

	
	if(result == -1)
		printf("Error Sending Packet\n");
	
}
/****************************************************
 * @param recvBuff - This is the buffer received
 * @param id - This is the interface id
 * This function is called when any type of ip packet
 * is received. The function forwards the packet if 
 * none of its ip addresses match the destination ip
 * address in the packet. Otherwise if it is the
 * destination and the packet is an icmp request it
 * creates the appropriate response
 **************************************************/
void recvIP(char recvBuf[1500], int id)
{
	char buf[98], tmpbuf[98];
	unsigned char *nextHop_mac;
        static unsigned short ip_id = 0;
        int offset = 0;
	int senderid = id;
        memcpy((void*)buf, (void*)recvBuf, 98);

        etherRepl = (struct ether_header *) recvBuf;
        offset += ETH_HDRLEN;
        iphdr = (struct ipHdr *) (recvBuf + offset);
        offset += IP4_HDRLEN;
	icmphdr = (struct icmpHdr *) (buf + offset);
        offset += ICMP_HDRLEN;

	unsigned char tmp[4], *tmp2;
        tmp[0] = iphdr->daddr[0];
        tmp[1] = iphdr->daddr[1];
        tmp[2] = iphdr->daddr[2];
        tmp[3] = iphdr->daddr[3];
        unsigned char nextHop[4];
	int i, j,k, max;
	j  = 0;
	max = 0;
	
	// These two while loops compare every interface
	// ip address with the destination in the ip packet
	// If there is a match max is set to 4	
	for(k = 0; k < 4; k++)
	{
		j = 0;
		for(i = 0; i < 4; i++)
		{
			if(iphdr->daddr[i] == src_ip[k][i])
			{
				j++;
			}	
			if(j > max)
				max = j;
		}
	}
	// If max = 4 then this is the destination
	if(max == 4)
	{
		// If this is an icmp request then send a response
		if(icmphdr->icmp_type == 8)
                {
                        printf("Sending icmp response\n");
                        buildIcmpResponse(buf, senderid);
             	}
        }
	// If this is not the destination the packet is forwarded
	else
	{
		// What is the next hop?
	        tmp2 = routeLookUp(tmp);
		// Which interface should we use to reach the next hop?
		id = getInterfaceIndex(iphdr->daddr);

		for(i = 0; i < 4; i++)
		{
			nextHop[i] = tmp2[i];
			tmp[i] = iphdr->daddr[i];
		}
		printf("tmp %2x:%2x:%2x:%2x\n", tmp[0],tmp[1],tmp[2],tmp[3]);
		printf("Next hop %x.%x.%x.%x\n", nextHop[0],nextHop[1],nextHop[2],nextHop[3]);
		memcpy(tmpbuf, buf, 98);
  
		/***************************************
		 * if the router hasn't logged the mac
		 * address of the destination then it
		 * will send out an arp request
		 * ********************************/		
		if(dest_mac[id][0] == '\0')
		{
			printf("Sending arp request\n");
			sendArpRequest(nextHop,id);
		}
		/*************************************************
		 * If it already has logged the mac address it
		 * will forward the packet
		 *************************************************/
		else
		{
			printf("Forwarding Packet\n");
			memcpy(etherRepl->ether_shost, src_mac[id], 6);
			memcpy(etherRepl->ether_dhost, dest_mac[id],6);
			offset = 0;
			memcpy((void*)etherRepl, buf, ETH_HDRLEN);
			offset += ETH_HDRLEN;
			memcpy((void*)iphdr, (void*)(buf+offset), IP4_HDRLEN);
			offset += IP4_HDRLEN;
			memcpy((void*)icmphdr, (void*)(buf+offset), ICMP_HDRLEN);
			offset += ICMP_HDRLEN;
			int result;
		        result = sendto(packet_socket[id], buf, sizeof(buf), 0,
				(struct sockaddr*) &recvaddr[id], sizeof(recvaddr));
		        if(result == -1)
               			 printf("Error Sending");
		}
	}
}
	
	

/*************************************************************
 * @param nextHop - The ip address of the next hop
 * @id - The id of the interface to reach this hop
 * This function sends an arp request in the event that the
 * node does not already know the mac address corresponding to
 * the ip of the next hop
 ************************************************************/
unsigned char* sendArpRequest(unsigned char nextHop[4], int id)
{
	char buf[42];
	struct ether_header *eth;
	struct arpReq *arp;
	eth = (struct ether_header*) buf;
	arp = (struct arpReq*) (buf + sizeof(struct ether_header));
	// Fill out the ethernet header
	memset(eth->ether_dhost, 0xffffff, 6);
	memcpy(eth->ether_shost, src_mac[id], sizeof(src_mac[id]));
	eth->ether_type = htons(0x0806);

	unsigned char *addr;
	unsigned char mac_addr[6];
	// Fill out the arp request
	arp->ar_hrd = htons(ARPHRD_ETHER);
        arp->ar_pro = htons(ETH_P_IP);
        arp->ar_hln = (0x06);
        arp->ar_pln = (0x04);
        arp->ar_op = htons(ARPOP_REQUEST);
	
	
	memcpy(arp->ar_sip, src_ip[id], 4);
        memcpy(arp->ar_sha, src_mac[id], 6);
        memset(arp->ar_tha, 0xffffff, 6);
        memcpy(arp->ar_tip, nextHop, 4);
	printf("Sending on interface %d\n", id);	
	
	int result = sendto(packet_socket[id], buf, sizeof(buf), 0,
		(struct sockaddr*) &recvaddr[id], sizeof(recvaddr));
	if(result == -1)
		printf("Error sending arp request\n");
}

void recvArpResponse(char buf[1500], int id)
{
        int result, offset,i;
	printf("Recieved arp response within Function called\n");
	struct ether_header *eth;
	eth = (struct ether_header *) buf;
        memcpy(dest_mac[id],eth->ether_shost,sizeof(eth->ether_shost));

	printf("Destination Mac on interface %d = ", id);
	for(i = 0; i < 6; i++)
		printf("%x:", dest_mac[id][i]);
	printf("\n");
}

buildIcmpResponse(char recvBuf[1500], int id)
{
	char buf[98];
	//static unsigned short ip_id = 0;
	int offset = 0;
	memcpy((void*)buf, (void*)recvBuf, 98);

	etherRepl = (struct ether_header *) buf;
	offset += ETH_HDRLEN;
	iphdr = (struct ipHdr *) (buf + offset);
	offset += IP4_HDRLEN;
	icmphdr = (struct icmpHdr *) (buf + offset);
	offset += ICMP_HDRLEN;
	
	/*************************
 	* Testing route lookup
 	*************************/

	offset = 0;
	memcpy((void*)etherRepl, buf, ETH_HDRLEN);
	offset += ETH_HDRLEN;
	memcpy((void*)iphdr, (void*)(buf+offset), IP4_HDRLEN);
	offset += IP4_HDRLEN;
	memcpy((void*)icmphdr, (void*)(buf+offset), ICMP_HDRLEN);
	offset += ICMP_HDRLEN;


	int i;
	for(i = 0; i < 6; i++ )
	{
		etherRepl->ether_dhost[i] = ether->ether_shost[i];
		etherRepl->ether_shost[i] = src_mac[id][i];
	}
	etherRepl->ether_type =htons( 0x0800);
	
	/* Construct the IP Header */
	iphdr->ihl = 5;
	iphdr->version = 4;
	iphdr->tos = 0;
	iphdr->frag_off = 0;
	iphdr->ttl = 20;
	iphdr->protocol = ICMP_PROTO;
	iphdr->check = 0;
	iphdr->check = ip_checksum((const void*)iphdr,sizeof(struct ipHdr));

	unsigned char tmp[4];
	memcpy((void*)tmp, (void*)iphdr->saddr, 4);
	memcpy((void*)iphdr->saddr,(void*) iphdr->daddr, 4);
	memcpy((void*)iphdr->daddr,(void*) tmp, 4);

	/* Construct icmp header */
	icmphdr->icmp_type = 0;
	icmphdr->icmp_chksum = 0;
//	icmphdr->icmp_chksum = ip_checksum((const void*)tmpbuf,sizeof(tmpbuf));


	offset = 0;
        memcpy((void*)buf, (void*)etherRepl, ETH_HDRLEN);
        offset += ETH_HDRLEN;
        memcpy((void*)(buf + offset), (void*)iphdr, IP4_HDRLEN);
        offset += IP4_HDRLEN;
        memcpy((void*)(buf + offset), (void*)icmphdr, ICMP_HDRLEN);
	icmphdr->icmp_chksum = ip_checksum((const void*)buf+offset, sizeof(struct icmpHdr) * 7);
	
	printf("%02X\n", buf + offset);
	memcpy((void*)(buf + offset), (void*)icmphdr, ICMP_HDRLEN);

	offset += ICMP_HDRLEN;


	int result;

	result = sendto(packet_socket[id], buf, sizeof(buf), 0,
		(struct sockaddr*) &recvaddr[id], sizeof(recvaddr));
	if(result == -1)
		printf("Error Sending");

}
