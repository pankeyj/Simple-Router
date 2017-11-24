#include <stdio.h>
#include <stdlib.h>
#include "help.h"


/*********************************************************
 * @param buf The header or buffer to calculate for
 * @param hdr_len The size of the header or buffer
 * @return sum The calculated check sum
 * This function caldculates the checksum value for the
 * ip header and the icmp headers. This is used to verify
 * the value received and insert the new value as well
 ***************************************************/
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

/*******************************************************
 * @param - dest Next Hop IP
 * @return id The index of the interface. -1 return if
 * it is not found
 * This function is used to find the interface to send
 * on to reach the next hop. It does this by finding the
 * last character(excluding the record separator so -2
 * from strlen). The last character is converted to a 
 * decimal value by taking the character value - 48
 ******************************************************/
int getInterfaceIndex(unsigned char dest[4])
{
	FILE *fp;
        char buf[50], s[2] = "/";
        char *token, ip[100];
        int prefix;
        unsigned char nextHop[4], tmp;

        fp = fopen("r1-table.txt", "r");
        if(fp == NULL)
                printf("File error");

	// Loop through each line in the routing table
        while(fgets(buf, sizeof(buf) ,fp))
        {
		// Find the last character before calling strtok
		int id;
		id = (buf[strlen(buf)-2]) - 48;

                token = strtok(buf, s);
                prefix = atoi(strtok(NULL, " "));
                strcpy(ip, "");
		// Compare each record with the next hop ip address
		// based on the length of the prefix for that record
		// Set ip to have the same prefix length without destroying
		// the original dest variable
		if(prefix == 24)
                {
                        sprintf(ip, "%u.%u.%u.%u", dest[0], dest[1], dest[2], (dest[3] & 0x0));
                }
                else if(prefix == 16)
                {
                        sprintf(ip, "%u.%u.%u.%u", dest[0], dest[1], (dest[2] & 0x0), (dest[3] & 0x0));
                }

		// If ip is equal to the token in the table then this is the
		// correct record and the id we found identifies the interface
		// correctly
		if(strcmp(token, ip) == 0)
		{
			return id;
		}
	}
	fclose(fp);
	return -1;
}

/******************************************************
 * @param dest - The IP destination address
 * @return nextHop - The IP address of the next hop. If
 * the next hop is the current destination returns same
 * value as the parameter.
 * This function is called to find the next hop address
 * when the destination is not the same as the current
 * node.It searches the routing table for a matching
 * prefix to the parameter dest.
 ******************************************************/
unsigned char* routeLookUp(unsigned char dest[4])
{
	FILE *fp;
	char buf[50], s[2] = "/";
	char *token, ip[100];
	int prefix;
	unsigned char nextHop[4], tmp;

	fp = fopen("r1-table.txt", "r");
	if(fp == NULL)
		printf("File error");
	// Read through each line of the fil
	while(fgets(buf, sizeof(buf) ,fp))
	{
		token = strtok(buf, s);
		prefix = atoi(strtok(NULL, " "));
		strcpy(ip, "");
		// Set ip equal to dest anded with the net mask
		if(prefix == 24)
		{
			sprintf(ip, "%u.%u.%u.%u", dest[0], dest[1], dest[2], (dest[3] & 0x0));
		}
		else if(prefix == 16)
		{
			sprintf(ip, "%u.%u.%u.%u", dest[0], dest[1], (dest[2] & 0x0), (dest[3] & 0x0));
		}
	
		/*********************************
 		* If our destination matches the prefix
 		* then we find the next hop ip
 		*********************************/
		if((strcmp(token, ip)) == 0)
		{
			// Next token is the destination
			token = strtok(NULL, " ");
			// Next hop and destination are the same if it is a dash
			if(strcmp(token, "-") == 0)
			{
				printf("Next Hop is the current destination\n");
				return dest;
			}
			else
			{
				// Copy each value to from the token to the new destination
				strcpy(dest,"");
				tmp = atoi(strtok(token, "."));
				dest[0] = tmp;
				tmp = atoi(strtok(NULL, "."));
				dest[1] = tmp;
				tmp = atoi(strtok(NULL, "."));
				dest[2] = tmp;				
				tmp = atoi(strtok(NULL, "."));
				dest[3] = tmp;	
				return dest;
			}					
		}
	}
	fclose(fp);	
		

}

