#include <stdio.h>
#include <stdlib.h>
#include "help.h"



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

int getInterfaceIndex(unsigned char dest[4])
{
	FILE *fp;
        char buf[50], s[2] = "/";
        char *token, ip[100];
        int prefix;
        unsigned char nextHop[4], tmp;

        fp = fopen("r2-table.txt", "r");
        if(fp == NULL)
                printf("File error");

        while(fgets(buf, sizeof(buf) ,fp))
        {
		int id;
		id = (buf[strlen(buf)-2]) - 48;

                token = strtok(buf, s);
                prefix = atoi(strtok(NULL, " "));
                strcpy(ip, "");
                if(prefix == 24)
                {
                        sprintf(ip, "%u.%u.%u.%u", dest[0], dest[1], dest[2], (dest[3] & 0x0));
                }
                else if(prefix == 16)
                {
                        sprintf(ip, "%u.%u.%u.%u", dest[0], dest[1], (dest[2] & 0x0), (dest[3] & 0x0));
                }
		if(strcmp(token, ip) == 0)
		{
			return id;
		}
	}
	return -1;
}

unsigned char* routeLookUp(unsigned char dest[4])
{
	FILE *fp;
	char buf[50], s[2] = "/";
	char *token, ip[100];
	int prefix;
	unsigned char nextHop[4], tmp;

	fp = fopen("r2-table.txt", "r");
	if(fp == NULL)
		printf("File error");

	while(fgets(buf, sizeof(buf) ,fp))
	{
		token = strtok(buf, s);
		prefix = atoi(strtok(NULL, " "));
		strcpy(ip, "");
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
			token = strtok(NULL, " ");
			if(strcmp(token, "-") == 0)
			{
				printf("Next Hop is the current destination\n");
				return dest;
			}
			else
			{
				strcpy(dest,"");
				tmp = atoi(strtok(token, "."));
				dest[0] = tmp;
				tmp = atoi(strtok(NULL, "."));
				dest[1] = tmp;
				tmp = atoi(strtok(NULL, "."));
				dest[2] = tmp;				
				tmp = atoi(strtok(NULL, "."));
				dest[3] = tmp;	
				printf("Next Hop ip %x%x%x%x\n)", dest[0],dest[1],dest[2],dest[3]);
				return dest;
			}					
		}
	}
	fclose(fp);	
		

}

