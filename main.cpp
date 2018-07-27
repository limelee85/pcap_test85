#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6
 
 /* ethernet headers are 14 bytes */
#define SIZE_ETHERNET 14
/* Ethernet header */
typedef struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN];     /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN];     /* Source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
} sniff_ethernet;

typedef struct sniff_ip {
        u_char ip_vhl;                  /* version << 4 | header length >> 2 */
        u_char ip_tos;                  /* type of service */
        u_short ip_len;                 /* total length */
#define     IP_HL(ip)    (((ip)->ip_vhl) & 0x0f)
#define     IP_V(ip)     (((ip)->ip_vhl) >> 4)
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char ip_ttl;                  /* time to live */
        u_char ip_p;                    /* protocol */
        u_short ip_sum;                 /* checksum */
        struct in_addr ip_src,ip_dst;   /* source and dest address */
} sniff_ip;

typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	//(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */		
} sniff_tcp;
#define IP_HEADER 0x0800
#define ARP_HEADER 0x0806
#define REVERSE_ARP_HEADER 0x0835
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n[_________PACKET_START________]\n");
    //printf("%u bytes captured\n", header->caplen);
    ethernet = (struct sniff_ethernet*)(packet);

    unsigned int ptype;
    ptype=ntohs(ethernet->ether_type);
    
    printf("[___________Ethernet__________]\n");
    printf("ether_shost [%02X:%02X:%02X:%02X:%02X:%02X]\nether_dhost [%02X:%02X:%02X:%02X:%02X:%02X]\n",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5],ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);

    if(ntohs(ethernet->ether_type) == IP_HEADER)
    {
	printf("[__________IP_HEADER__________]\n");
	u_int size_ip;
	ip = (const struct sniff_ip *)(packet+14);
	size_ip = IP_HL(ip)*4;
	//size_ip = (ip->ip_len)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return(1);
	}
	printf("ip_src %s\nip_dst %s\n",inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));
	if((ip->ip_p)== 0x06){
		tcp = (const struct sniff_tcp *)(packet+14+size_ip);
		u_int size_tcp;
		size_tcp = (tcp->th_offx2)*4;
		if (size_tcp < 20) {
		    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		    return(1);
		}
		printf("[__________TCP_HEADER_________]\n");
		printf("th_sport %d\nth_dport %d\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));
		const char *payload; /* Packet payload */
		payload = (char *)(packet+14+size_ip+size_tcp);
		printf("[_____________DATA____________]\n");
		for(size_t i=0;i<16;i++){
			if(i!=0&&(i%4)==0){
				printf("\n");
			}
			printf("%s%02X", (i ? " " : " "),payload[i]);
		}
		printf("\n");
	}
    }
  
    printf("[__________PACKET_END_________]\n\n");
  }
  pcap_close(handle);
  return 0;
}
