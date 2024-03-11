#include "Headers/snifed.h"


Snifed::~Snifed() {

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

    myheader_ip->Internetl="test";
    myheader_ip->Transportl="test";


    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {

       Ui::arppacket *arp_header=(struct Ui::arppacket *)(buffer+sizeof(ether_header));
       myheader_ip->Internetl="ARP";
       myheader_ip->Transportl="ARP";

       myheader_ip->Dadder= destMacStr;
       myheader_ip->Sadder= sourceMacStr;


    }
    if(ntohs(eth_header->ether_type)==ETHERTYPE_REVARP ){
     //   Ui::arppacket *arp_header=(struct Ui::arppacket *)(buffer+sizeof(ether_header));
        myheader_ip->Internetl="ARP";
        myheader_ip->Transportl="ARP";
    }
    if(ntohs(eth_header->ether_type)==ETHERTYPE_LOOPBACK){
       // Ui::arppacket *arp_header=(struct Ui::arppacket *)(buffer+sizeof(ether_header));
        myheader_ip->Internetl="LoopBack";
        myheader_ip->Transportl="LoopBack";
    }
    if(ntohs(eth_header->ether_type)==ETHERTYPE_PUP ){
        myheader_ip->Internetl="PUP";
        myheader_ip->Transportl="PUP";


    }
    if(ntohs(eth_header->ether_type)==ETHERTYPE_SPRITE ){
        myheader_ip->Internetl="SPRITE";
        myheader_ip->Transportl="SPRITE";
    }
    if(ntohs(eth_header->ether_type)==ETHERTYPE_AARP ){
        myheader_ip->Internetl="AARP";
        myheader_ip->Transportl="AARP";
    }
    if(ntohs(eth_header->ether_type)==ETHERTYPE_AT ){
        myheader_ip->Internetl="AT";
        myheader_ip->Transportl="AT";
    }
    if(ntohs(eth_header->ether_type)==ETHERTYPE_VLAN ){
        myheader_ip->Internetl="VLAN";
        myheader_ip->Transportl="VLAN";
    }
    if(ntohs(eth_header->ether_type)==ETHERTYPE_TRAIL){
        myheader_ip->Internetl="TRAIL";
        myheader_ip->Transportl="TRAIL";
    }
    if(ntohs(eth_header->ether_type)==ETHERTYPE_NTRAILER){
        myheader_ip->Internetl="NTRAILER";
        myheader_ip->Transportl="NTRAILER";
    }






    if(ntohs(eth_header->ether_type)==ETHERTYPE_IP ){

        myheader_ip->Internetl="IPv4";
        myheader_ip->Transportl="IPv4";

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
                myheader_ip->data=buffer+sizeof(ether_header)+len;
                if (!Snifed::checkPort(ntohs(tcp_header->th_sport)).empty()) {
                    myheader_ip->msg = Snifed::checkPort(ntohs(tcp_header->th_sport));





                }else{
                    myheader_ip->msg = Snifed::checkPort(ntohs(tcp_header->th_dport));
                }


            }
             if(strcmp(proto_info->p_name,"udp")==0){
               udphdr *udp_header=(struct udphdr *)(buffer+sizeof(ether_header)+len);
                myheader_ip->sport=ntohs(udp_header->uh_sport);
                myheader_ip->dport=ntohs(udp_header->uh_dport);

                if (!Snifed::checkPort(ntohs(udp_header->uh_sport)).empty()) {
                    myheader_ip->msg = Snifed::checkPort(ntohs(udp_header->uh_sport));
                }else{
                    myheader_ip->msg = Snifed::checkPort(ntohs(udp_header->uh_dport));

                }
                if(strcmp(proto_info->p_name,"IGMP")==0 || strcmp(proto_info->p_name,"igmp")==0){
                    myheader_ip->Transportl = "igmp";




                }




             }
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


Ui::myip *Snifed::getIPhdr() {

    return myheader_ip.get();
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

