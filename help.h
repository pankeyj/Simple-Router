#include <string.h>
unsigned short int ip_checksum(const void* buf, size_t hdr_len);
unsigned char* routeLookUp(unsigned char dest[4]);
int getInterfaceIndex(unsigned char dest[4]);
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

