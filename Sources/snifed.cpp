#include "Headers/snifed.h"


Snifed::~Snifed() {
    // No need to explicitly release myheader_ip, std::unique_ptr will handle it.
}

Snifed::Snifed(char *buffer)
{
    struct ether_header *eth_header = (struct ether_header *)buffer;
    Snifed::myheader_ip=nullptr;
    myheader_ip = std::make_unique<Ui::myip>();
    myheader_ip->Linkl="ETHERNET";
    myheader_ip->myeth=eth_header;
    struct ether_addr source;
    memcpy(source.ether_addr_octet, eth_header->ether_shost, ETHER_ADDR_LEN);
    char sourceMacStr[ETHER_ADDR_LEN * 3];
    strcpy(sourceMacStr, ether_ntoa(&source));
    myheader_ip->Smacaddr = sourceMacStr;

    struct ether_addr dest;
    memcpy(dest.ether_addr_octet,eth_header->ether_dhost , ETHER_ADDR_LEN);
    char destMacStr[ETHER_ADDR_LEN * 3];
    strcpy(destMacStr, ether_ntoa(&dest));
    myheader_ip->Dmacaddr = destMacStr;



    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {

        Ui::arppacket *arp_header=(struct Ui::arppacket *)(buffer+sizeof(ether_header));
        myheader_ip->Internetl="ARP";
       myheader_ip->Transportl="ARP";
    }

    if(ntohs(eth_header->ether_type)==ETHERTYPE_IP ){

            myheader_ip->Internetl="IPv4";

            iphdr *ip_header=(struct iphdr *)(buffer+sizeof(ether_header));
             struct protoent *proto_info = getprotobynumber(ip_header->protocol);
            if (proto_info != nullptr) {
                 if(proto_info->p_name!=nullptr){
                    int len=ip_header->ihl * 4;
                    myheader_ip->Sadder=inet_ntoa(*(struct in_addr *)&(ip_header->saddr));
                     myheader_ip->Dadder=inet_ntoa(*(struct in_addr *)&(ip_header->daddr));
                    myheader_ip->Transportl=proto_info->p_name;


             if(strcmp(proto_info->p_name,"tcp")==0){

                tcphdr *tcp_header=(struct tcphdr *)(buffer+sizeof(ether_header)+len);
                 myheader_ip->sport=ntohs(tcp_header->th_sport);
                myheader_ip->dport=ntohs(tcp_header->th_dport);
                if (!Snifed::checkPort(ntohs(tcp_header->th_sport)).empty()) {
                    myheader_ip->msg = Snifed::checkPort(ntohs(tcp_header->th_sport)); // Move ownership to myheader_ip->msg
                }else{
                    myheader_ip->msg = Snifed::checkPort(ntohs(tcp_header->th_dport)); // Move ownership to myheader_ip->msg
                }

            }
             if(strcmp(proto_info->p_name,"udp")==0){
               udphdr *udp_header=(struct udphdr *)(buffer+sizeof(ether_header)+len);
                myheader_ip->sport=ntohs(udp_header->uh_sport);
                myheader_ip->dport=ntohs(udp_header->uh_dport);

                if (!Snifed::checkPort(ntohs(udp_header->uh_sport)).empty()) {
                    myheader_ip->msg = Snifed::checkPort(ntohs(udp_header->uh_sport)); // Move ownership to myheader_ip->msg
                }else{
                    myheader_ip->msg = Snifed::checkPort(ntohs(udp_header->uh_dport)); // Move ownership to myheader_ip->msg

                }



             }
                 }


                 else {
            ip_header=nullptr;
            proto_info=nullptr;
                 }

            }
            else {
            ip_header=nullptr;
            proto_info=nullptr;
            }

    }
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {

            myheader_ip->Internetl = "IPv6";

            ip6_hdr *ipv6_header = (ip6_hdr *)(buffer + sizeof(ether_header));

            struct protoent *proto_info = nullptr;
            struct tcphdr *tcp_header=nullptr;
            struct udphdr *udp_header=nullptr;
            uint8_t next_header = (ipv6_header->ip6_nxt);

            switch (next_header) {
            case IPPROTO_TCP:
            myheader_ip->Transportl = "tcp";
             tcp_header = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            myheader_ip->sport = ntohs(tcp_header->th_sport);
            myheader_ip->dport = ntohs(tcp_header->th_dport);
            if (!Snifed::checkPort(ntohs(tcp_header->th_sport)).empty()) {
            myheader_ip->msg = Snifed::checkPort(ntohs(tcp_header->th_sport));
            } else {
            myheader_ip->msg = Snifed::checkPort(ntohs(tcp_header->th_dport));
            }
            break;
            case IPPROTO_UDP:
            myheader_ip->Transportl = "udp";
            udp_header = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            myheader_ip->sport = ntohs(udp_header->uh_sport);
            myheader_ip->dport = ntohs(udp_header->uh_dport);
            if (!Snifed::checkPort(ntohs(udp_header->uh_sport)).empty()) {
            myheader_ip->msg = Snifed::checkPort(ntohs(udp_header->uh_sport));
            } else {
            myheader_ip->msg = Snifed::checkPort(ntohs(udp_header->uh_dport));
            }
            break;
            case IPPROTO_ICMPV6:
            myheader_ip->Transportl = "icmpv6";
            break;
            default:
            myheader_ip->Transportl = "ipv6";
            }

            char src_ipv6_str[INET6_ADDRSTRLEN];
            char dst_ipv6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6_header->ip6_src), src_ipv6_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dst_ipv6_str, INET6_ADDRSTRLEN);

            myheader_ip->Sadder = src_ipv6_str;
            myheader_ip->Dadder = dst_ipv6_str;




            // Handle various IPv6 next header types

            if (proto_info != nullptr) {
            char src_ipv6_str[INET6_ADDRSTRLEN];
            char dst_ipv6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6_header->ip6_src), src_ipv6_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dst_ipv6_str, INET6_ADDRSTRLEN);

            myheader_ip->Sadder = src_ipv6_str;
            myheader_ip->Dadder = dst_ipv6_str;
            myheader_ip->Transportl = proto_info->p_name;

            if (next_header == IPPROTO_TCP) {
            tcphdr *tcp_header = (struct tcphdr *)(buffer + sizeof(ether_header) + sizeof(ip6_hdr));
            myheader_ip->sport = ntohs(tcp_header->th_sport);
            myheader_ip->dport = ntohs(tcp_header->th_dport);

            if (!Snifed::checkPort(ntohs(tcp_header->th_sport)).empty()) {
                myheader_ip->msg = Snifed::checkPort(ntohs(tcp_header->th_sport)); // Move ownership to myheader_ip->msg
            } else {
                myheader_ip->msg = Snifed::checkPort(ntohs(tcp_header->th_dport)); // Move ownership to myheader_ip->msg
            }
            } else if (next_header == IPPROTO_UDP) {
            udphdr *udp_header = (struct udphdr *)(buffer + sizeof(ether_header) + sizeof(ip6_hdr));
            myheader_ip->sport = ntohs(udp_header->uh_sport);
            myheader_ip->dport = ntohs(udp_header->uh_dport);

            if (!Snifed::checkPort(ntohs(udp_header->uh_sport)).empty()) {
                myheader_ip->msg = Snifed::checkPort(ntohs(udp_header->uh_sport));
            } else {
                myheader_ip->msg = Snifed::checkPort(ntohs(udp_header->uh_dport));
            }
            }
            }

        }


}


/*
Snifed::Snifed(char *buffer) {
    ether_header *eth_header = (ether_header *)buffer;

    if (eth_header->ether_type == ETHERTYPE_ARP) {
        // Handle ARP packets if needed
    }

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        Snifed::myheader_ip = (myip *)malloc(sizeof(myip));
        if (Snifed::myheader_ip != nullptr) {  // Check if memory allocation is successful
            iphdr *ip_header = (struct iphdr *)(buffer + sizeof(char) * 14);
            int len = ip_header->ihl * 4;
            struct protoent *proto_info = getprotobynumber(ip_header->protocol);

            if (proto_info != nullptr) {
                strcpy(Snifed::myheader_ip->Sadder, inet_ntoa(*(struct in_addr *)&(ip_header->saddr)));
                strcpy(Snifed::myheader_ip->Dadder, inet_ntoa(*(struct in_addr *)&(ip_header->daddr)));

                // Make sure to allocate enough space for the protocol name
                Snifed::myheader_ip->Pname = (char *)malloc(strlen(proto_info->p_name) + 1);
                if (Snifed::myheader_ip->Pname != nullptr) {
                    strcpy(Snifed::myheader_ip->Pname, proto_info->p_name);
                } else {
                    // Handle memory allocation failure for Pname
                }
            } else {
                // Handle protocol info not found
            }
        } else {
            // Handle memory allocation failure for myheader_ip
        }
    }
}*/
/*
            if(strcmp(proto_info->p_name,"tcp")==0){
                //tcphdr *tcp_header=(struct tcphdr *)(ip_header+sizeof(char)*len);
                //    Snifed::myheader_ip->Pname=(char*)malloc(sizeof(char)*6);
                //  strcpy(Snifed::myheader_ip->Pname,"tcp");
                // Snifed::myheader_ip->msg= (char*)malloc(sizeof(char)*strlen(Snifed::checkPort(ntohs(tcp_header->th_sport))));
                //  Snifed::myheader_ip->msg=Snifed::checkPort(ntohs(tcp_header->th_sport));
                //    Snifed::myheader_ip->port=ntohs(tcp_header->th_sport);
            }

            if(strcmp(proto_info->p_name,"udp")==0){
                // udphdr *udp_header=(struct udphdr *)(ip_header+sizeof(char)*len);
                // Snifed::myheader_ip->Pname=(char*)malloc(sizeof(char)*6);
                //strcpy(Snifed::myheader_ip->Pname,"udp");
                //   Snifed::myheader_ip->msg= (char*)malloc(sizeof(char)*strlen(Snifed::checkPort(ntohs(udp_header->uh_sport))));
                //     Snifed::myheader_ip->msg=Snifed::checkPort(ntohs(udp_header->uh_sport));
                //  Snifed::myheader_ip->port=ntohs(udp_header->uh_sport);
            }
            */

Ui::myip *Snifed::getIPhdr() {

    return myheader_ip.get(); // Return the local myip object by value (copy)
}


std::string Snifed::checkPort(int p) {
    std::string buff ;

    switch (p) {
    case 21:
        buff= "FTP";
        break;

    case 22:
        buff= "SSH";
        break;

    case 23:
        buff ="Telnet";
        break;

    case 25:
        buff =  "SMTP";
        break;

    case 53:
        buff =  "DNS";
        break;

    case 80:
        buff =  "HTTP";
        break;

    case 110:
        buff =  "POP3";
        break;
    case 123:
        buff = "NTP";
        break;
    case 137:
        buff = "NBNS";
        break;



    case 143:
        buff = "IMAP";
        break;

    case 443:
        buff =  "HTTPS";
        break;

    case 67:
        buff =  "DHCP";
        break;



    case 68:
        buff =  "DHCP";
        break;

    case 1900:
        buff ="SSDP";
        break;



    case 3306:
        buff =  "MySQL";
        break;

    case 3389:
        buff = "RDP";
        break;

    case 5432:
        buff =  "PostgreSQL";
        break;
    case 5353:
        buff = "MDNS";
        break;
    case 51355:
        buff = "MDNS";
        break;




     //   buff=nullptr;
    }

    return buff;
}

