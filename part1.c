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

struct arpReq {
	unsigned short int ar_hrd;
	unsigned short int ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	unsigned short int ar_op;
	unsigned char ar_sha[6];
	unsigned char ar_sip[4];
	unsigned char ar_tha[6];
	unsigned char ar_tip[4];
	// Padding
	char padding[18];
};

struct ipHdr { 
 
	unsigned char	ihl:4, 
			version:4; 
	unsigned char	tos; 
	unsigned short	tot_len; 
	unsigned short	id; 
	unsigned short	frag_off; 
	unsigned char	ttl; 
	unsigned char	protocol; 
	unsigned short	check; 
	unsigned char	saddr[4]; 
	unsigned char	daddr[4]; 
	/*The options start here. */ 
};

struct ether_arp {
	unsigned char arp_sha[6];
	unsigned char arp_spa[4];
	unsigned char arp_tha[6];
	unsigned char arp_tpa[4];
};

struct icmpHdr {
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short int icmp_chksum;
	unsigned short int icmp_ident;
	unsigned short int icmp_seqnum;
};
struct icmpHdr *icmphdr, *echoReqIcmp;
struct ipHdr *iphdr, *echoReqIp;
struct ifreq if_mac;
struct ether_header* ether;
struct ether_header* etherRepl;
struct arpReq* arpReq;
struct arphdr* arpRepl;
void buildArpResponse();
struct sockaddr_ll recvaddr;
int packet_socket;
u_int8_t src_mac[6];


int main(){
  //get list of interfaces (actually addresses)
  char buf[1500];
  struct ifaddrs *ifaddr, *tmp;
  if(getifaddrs(&ifaddr)==-1){
    perror("getifaddrs");
    return 1;
  }
  //have the list, loop over the list
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
    //Check if this is a packet address, there will be one per
    //interface.  There are IPv4 and IPv6 as well, but we don't care
    //about those for the purpose of enumerating interfaces. We can
    //use the AF_INET addresses in this list for example to get a list
    //of our own IP addresses
    /****************************************
    * Looking for mac address
    * ***************************************/
 
    if(tmp->ifa_addr->sa_family==AF_PACKET){
      printf("Interface: %s\n",tmp->ifa_name);
      //create a packet socket on interface r?-eth1
	struct sockaddr_ll *s = (struct sockaddr_ll *) tmp->ifa_addr;
	int i;
        int len = 0;
        for(i = 0; i < 6; i++)
		printf("%02X%s",s->sll_addr[i],i < 5 ? ":":"\n");

      if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
	printf("Creating Socket on interface %s\n",tmp->ifa_name);
	//create a packet socket
	//AF_PACKET makes it a packet socket
	//SOCK_RAW makes it so we get the entire packet
	//could also use SOCK_DGRAM to cut off link layer header
	//ETH_P_ALL indicates we want all (upper layer) protocols
	//we could specify just a specific one
	for(i = 0; i < 6; i++)
		src_mac[i] = s->sll_addr[i];

	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(packet_socket<0){
	  perror("socket");
	  return 1;
	}
	//Bind the socket to the address, so we only get packets
	//recieved on this specific interface. For packet sockets, the
	//address structure is a struct sockaddr_ll (see the man page
	//for "packet"), but of course bind takes a struct sockaddr.
	//Here, we can use the sockaddr we got from getifaddrs (which
	//we could convert to sockaddr_ll if we needed to)
	if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
	  perror("bind");
	}
      }
    }
  }
  //free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);

  //loop and recieve packets. We are only looking at one interface,
  //for the project you will probably want to look at more (to do so,
  //a good way is to have one socket per interface and use select to
  //see which ones have data)
  printf("Ready to recieve now\n");
  while(1){


    int recvaddrlen=sizeof(struct sockaddr_ll);
    //we can use recv, since the addresses are in the packet, but we
    //use recvfrom because it gives us an easy way to determine if
    //this packet is incoming or outgoing (when using ETH_P_ALL, we
    //see packets in both directions. Only outgoing can be seen when
    //using a packet socket with some specific protocol)
    int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
    //ignore outgoing packets (we can't disable some from being sent
    //by the OS automatically, for example ICMP port unreachable
    //messages, so we will just ignore them here)
    if(recvaddr.sll_pkttype==PACKET_OUTGOING)
      continue;
    //start processing all other
    printf("Got a %d byte packet\n", n);
   	   
    //what else to do is up to you, you can send packets with send,
    //just like we used for TCP sockets (or you can use sendto, but it
    //is not necessary, since the headers, including all addresses,
    //need to be in the buffer you are sending)
   
/*****************************************
	This is my code
*****************************************/


	/* Contains physical addresses and type of message */
	int offset = 0;	
	ether = (struct ether_header*) buf;
	offset += sizeof(struct ether_header);
	/*** unsure about htons but it works for now ***/
	if((htons(ether->ether_type)) == ETHERTYPE_ARP)
	{
		printf("Recieved an arp packet\n");
		arpReq = (struct arpReq *) (buf + offset);
		buildArpResponse();
	}
	else
	{
		printf("Recieved another type of packet\n");
//		echoReqIp = (struct ipHdr *) (buf + offset);
//		offset += sizeof(struct ipHdr);
//		echoReqIcmp = (struct icmpHdr *) (buf + offset);
		buildIcmpResponse(buf);
	}
}
  //exit
  return 0;
}

void buildArpResponse()
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
	memcpy(arpEnd->arp_sha, src_mac, 6);
	memcpy(arpEnd->arp_tha, ether->ether_shost, 6);
	memcpy(arpEnd->arp_tpa, arpReq->ar_sip, 4);
	int i;
	for(i = 0; i < 6; i++ )
	{
		etherRepl->ether_dhost[i] = ether->ether_shost[i];
		etherRepl->ether_shost[i] = src_mac[i];	
	}
	etherRepl->ether_type = ether->ether_type;
	
	memcpy((void*)buf, (void*) etherRepl, sizeof(struct ether_header));
	offset += sizeof(struct ether_header);
	memcpy((void*)(buf + offset), (void*) arpRepl, sizeof(struct arphdr));	
	offset += sizeof(struct arphdr);
	memcpy((void*)buf + offset, (void*)arpEnd, sizeof(struct ether_arp));
	result = sendto(packet_socket, buf, sizeof(buf), 0,
		(struct sockaddr*) &recvaddr, sizeof(recvaddr));

	
	if(result == -1)
		printf("Error Sending Packet\n");
	
}



unsigned short int ip_checksum(const void * buf, size_t hdr_len)
{
        unsigned long sum = 0;
        const unsigned short int *ip;
        ip = buf;
        while(hdr_len > 1)
        {
                sum += *ip++;
                if(sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                hdr_len -= 2;
        }

        while(sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return(~sum);
}



buildIcmpResponse(char recvBuf[1500])
{
	char buf[98];
	static unsigned short ip_id = 0;
	int offset = 0;
	memcpy((void*)buf, (void*)recvBuf, 98);

	etherRepl = (struct ether_header *) buf;
	offset += ETH_HDRLEN;
	iphdr = (struct ipHdr *) (buf + offset);
	offset += IP4_HDRLEN;
	icmphdr = (struct icmpHdr *) (buf + offset);
	offset += ICMP_HDRLEN;
	
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
		etherRepl->ether_shost[i] = src_mac[i];
	}
	etherRepl->ether_type =htons( 0x0800);
	
	/* Construct the IP Header */
	iphdr->ihl = 5;
	iphdr->version = 4;
	iphdr->tos = 0;
	iphdr->tot_len = htons(32);
//	iphdr->id = htons(ip_id++);
	iphdr->frag_off = 0;
	iphdr->ttl = 20;
	iphdr->protocol = ICMP_PROTO;
	iphdr->check = 0;
	iphdr->check = ip_checksum((const void*)iphdr,(size_t) IP4_HDRLEN);

	unsigned char tmp[4];
	printf("Source: %u\n", iphdr->saddr);
	printf("Dest: %u\n", iphdr->daddr);
	memcpy((void*)tmp, (void*)iphdr->saddr, 4);
	memcpy((void*)iphdr->saddr,(void*) iphdr->daddr, 4);
	memcpy((void*)iphdr->daddr,(void*) tmp, 4);
//	iphdr->saddr = htons(iphdr->daddr);
//	iphdr->daddr = htons(tmp);

	/* Construct icmp header */
	icmphdr->icmp_type = 0;
//	icmphdr->icmp_code = 0;
	icmphdr->icmp_chksum = ip_checksum((const void*)icmphdr,(size_t) ICMP_HDRLEN);
//	icmphdr->icmp_ident = echoReqIcmp->icmp_ident;
//	icmphdr->icmp_seqnum = echoReqIcmp->icmp_seqnum;
	/*
	memcpy((void*)buf, (void*) etherRepl, sizeof(struct ether_header));
	offset += sizeof(struct ether_header);
	memcpy((void*)(buf + offset), (void*) iphdr, sizeof(struct ipHdr));
	offset += sizeof(struct ipHdr);
	memcpy((void*)buf + offset, (void*) icmphdr, sizeof(struct icmp));
	*/
	int result;
	result = sendto(packet_socket, buf, sizeof(buf), 0,
		(struct sockaddr*) &recvaddr, sizeof(recvaddr));
	if(result == -1)
		printf("Error Sending");

}
