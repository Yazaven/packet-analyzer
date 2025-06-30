#ifndef SNIFED_H
#define SNIFED_H

#include "packetd.h"
#include <memory>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdint.h>
#include <malloc.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <memory>
#include <netinet/ether.h>
#include <netinet/ip6.h>



class Snifed
{

public:
    std::string checkPort(int p);
    Snifed(char *buffer);
    ~Snifed();
    Ui::myip *getIPhdr();


private:
    std::unique_ptr<Ui::myip> myheader_ip;
};

#endif 
