#include <net/ethernet.h> // use ethernet protocol 
#include <netinet/ip.h> // use ip protocol 
#include <netinet/in.h> // use header struct
#include <arpa/inet.h> // change byte order to funtions
#include <pcap.h> // use pcap libary
#include <stdio.h> // std input output
#include <stdint.h> // define u_int 

struct pcap_pkthdr* header;
const u_char* packet;

#define ETHER_LEN 6 
#define SIZE_ETHERNET 14
struct ethernet_header
{
    u_char ether_dhost[ETHER_LEN]; // distitation MAC
    u_char ether_shost[ETHER_LEN]; // source MAC 
    u_short ether_type; // ethernet type
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
u_int size_ip;
struct ip_header 
{
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_protocol; // ip type ( use check next protocol )
    u_short ip_sum;
    struct in_addr ip_src; // source IP 
    struct in_addr ip_dst; // distitation IP 
};

u_int size_tcp;
typedef u_int tcp_seq;
struct tcp_header 
{
    u_short th_sport; // source TCP
    u_short th_dport; // distitaion TCP
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
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
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

struct ethernet_header *ethernet; // Ethernet header
struct ip_header *ip; // IP header
struct tcp_header *tcp; // TCP header

void Usage() 
{
    puts("syntax: pcap_test <interface>");
    puts("sample: pcap_test wlan0");
}

void MakeLine(int num)
{
    for(int i=1; i<=num; i++)
        printf("\n");
}

void CapturedPacket(int size)
{
    puts("###### Captured Packet ######");
    printf("[+] Captured size : %u\n", size);
}

void PrintMac()
{
    ethernet = (struct ethernet_header*)(packet);

	puts("###### Ethernet Header ######");
	printf("[+] Mac Source Address : ");
	for(int i=0; i<ETHER_LEN; i++)
    {
        if(i!=0)
            printf(":");
        printf("%02X", ethernet->ether_shost[i]);
    }
    MakeLine(1);

	printf("[+] Mac Destination Address : ");
    for(int i=0; i<ETHER_LEN; i++)
    {
        if(i!=0)
            printf(":");
        printf("%02X", ethernet->ether_dhost[i]);
    }
    MakeLine(1);   
    
    if(ntohs(ethernet->ether_type) == ETHERTYPE_IP)
        puts("[+] Next protocol : IP");
}

void PrintIP()
{
    ip = (struct ip_header*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;

	puts("###### IP Header ######");
    printf("[+] IP Source Address : %s\n", inet_ntoa(ip->ip_src));
    printf("[+] IP Destination Address : %s\n", inet_ntoa(ip->ip_dst));    
    
    if(ip->ip_protocol == IPPROTO_TCP)
        puts("[+] Next protocol : TCP");
}

void PrintTCP()
{
    tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;

    puts("###### TCP Header ######");
    printf("[+] TCP Source Port : %d\n", ntohs(tcp->th_sport));
    printf("[+] TCP Destination Port : %d\n", ntohs(tcp->th_dport));
}

void PrintData()
{
    u_char *data = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    int data_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
    
    puts("###### DATA ######");

    if(data_len == 0)
    {
        puts("[+] data length : 0");
        puts("[!] Notice : No data in packet!");
        return ;
    }

    if(data_len < 10)
    {
        if(data_len == 1)
        {
            printf("[+] data length : %d\n", data_len);
            puts("[!] Print 1 bytes of data ");
        }
        else
        {
            printf("[+] data length : %d\n", data_len);
            printf("[!] Print %d bytes of data\n", data_len);
        }
    }  

    else
    {
        printf("[+] data length : %d\n", data_len);
        puts("[!] Print 10 bytes of data");
    }
       
    printf("-> ");
    for(int i=1; i<data_len + 1; i++)
    {
        printf("%02X ", data[i - 1]);
        if(i==10)
            break;
    }

    MakeLine(1);
}

int main(int argc, char* argv[]) 
{
    if (argc != 2) 
    {
        Usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "[!] Notice : Can't open device! %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) 
    {
        int res = pcap_next_ex(handle, &header, &packet);
        
        if (res == 0) 
	        continue;
        if (res == -1 || res == -2) 
	        break;
       
        int captured_size = header->caplen;
        CapturedPacket(captured_size);

	    PrintMac();
		PrintIP();
        PrintTCP();
        PrintData();

	    MakeLine(1);	
    }

    pcap_close(handle);
    
    return 0;
}
