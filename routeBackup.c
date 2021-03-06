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


struct ether_arp {
	unsigned char arp_sha[6];
	unsigned char arp_spa[4];
	unsigned char arp_tha[6];
	unsigned char arp_tpa[4];
};
struct ifreq if_mac;
struct ether_header* ether;
struct ether_header* etherRepl;
struct arpReq* arpReq;
struct arphdr* arpRepl;
char buf[1500];
void buildArpResponse();
struct sockaddr_ll recvaddr;
int packet_socket;

int main(){
  //get list of interfaces (actually addresses)
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
    if(tmp->ifa_addr->sa_family==AF_PACKET){
      printf("Interface: %s\n",tmp->ifa_name);
      //create a packet socket on interface r?-eth1
      if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
	printf("Creating Socket on interface %s\n",tmp->ifa_name);
	//create a packet socket
	//AF_PACKET makes it a packet socket
	//SOCK_RAW makes it so we get the entire packet
	//could also use SOCK_DGRAM to cut off link layer header
	//ETH_P_ALL indicates we want all (upper layer) protocols
	//we could specify just a specific one
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
	
	ether = (struct ether_header*) (buf);
	/*
	printf("\t|-Ethernet D Host: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
		ether->ether_dhost[0],ether->ether_dhost[1],ether->ether_dhost[2],
		ether->ether_dhost[3],ether->ether_dhost[4],ether->ether_dhost[5]);
	printf("\t|-Ethernet S Host: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
		ether->ether_shost[0],ether->ether_shost[1],ether->ether_shost[2],
		ether->ether_shost[3],ether->ether_shost[4],ether->ether_shost[5]);
	printf("\t|-Ethernet Type  : %hu\n", ether->ether_type);
	*/
	/*** unsure about htons but it works for now ***/
	if((htons(ether->ether_type)) == ETHERTYPE_ARP)
	{
		printf("Recieved an arp packet\n");
		arpReq = (struct arpReq *) ((sizeof(struct ether_header)) + (buf));
		/*
		printf("Sender IP Address %.2X . %.2X . %.2X . %.2X\n",
			arpReq->sender_ip[0], arpReq->sender_ip[1],
			arpReq->sender_ip[2], arpReq->sender_ip[3]);
		printf("Target IP Address %.2X . %.2X . %.2X . %.2X\n",
			arpReq->target_ip[0], arpReq->target_ip[1],
			arpReq->target_ip[2], arpReq->target_ip[1]);
		*/
		buildArpResponse();
	}
	else
	{
		printf("Recieved another type of packet\n");
	}
	
	
	/**************************************************
 	* IP header is only present when it is an IP packet.
 	* Arp Packets must use something else. Can't find
 	* the include for the arp header so I'll just make
 	* my own.
 	*************************************************/
}
  //exit
  return 0;
}

void buildArpResponse()
{
//	struct arphdr *arp_rsp;
	struct ether_arp *arpEnd;
	int result, offset;
	etherRepl = (struct ether_header *) buf;
	arpRepl = (struct arphdr *) buf + (sizeof(struct ether_header));
	arpEnd = (struct ether_arp *) buf + ((sizeof(struct ether_header)) + (sizeof(struct arphdr)));
	u_int8_t src_mac[6] = {0x6a, 0x0f, 0xb8, 0x42, 0xaa, 0xe2};
	

	
	arpRepl->ar_hrd = htons(ARPHRD_ETHER);
	arpRepl->ar_pro = htons(ETH_P_IP);
	arpRepl->ar_hln = 0x06;
	arpRepl->ar_pln = 0x04;
	arpRepl->ar_op = htons(ARPOP_REPLY);

	unsigned char tmpha[6];
	unsigned char tmppa[4];
//	printf("Temp Hardwar Address %2X, %2X, %2X, %2X\n", tmpha[0], tmpha[1], tmpha[2], tmpha[3]);
//emcpy(tmpha, arpEnd->arp_spa, 4);
	memcpy(arpEnd->arp_spa, arpReq->ar_tip, 4);
	memcpy(arpEnd->arp_sha, src_mac, 6);
	memcpy(arpEnd->arp_tha, ether->ether_shost, 6);
	memcpy(arpEnd->arp_tpa, arpReq->ar_sip, 4);

	/*
	memcpy(arp_rsp->ar_sha, arp_entrys.ar_ha, ETH_ALEN);
	arp_rsp->ar_sip = arp_hdr->tip;
	memcpy(arp_rsp->ar_tha, arpRepl->->ar_sha, ETH_ALEN);
	arp_rsp->ar_tip = arp_hdr->ar_sip;
	*/	

	int i;
	for(i = 0; i < 6; i++ )
	{
		etherRepl->ether_dhost[i] = ether->ether_shost[i];
		etherRepl->ether_shost[i] = src_mac[i];	
	}
	etherRepl->ether_type = ether->ether_type;
	
//	memset(buf, 0, sizeof(buf));
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



