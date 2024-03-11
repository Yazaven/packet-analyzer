#ifndef PACKETD_H
#define PACKETD_H

#include <QMainWindow>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <QTreeWidgetItem>
#include "ui_packetd.h"
#include <QWidget>
#include <qstring.h>


namespace Ui {
struct arppacket {
    struct arphdr arph;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
};



typedef struct myip{
    myip(){


    }
    std::string Linkl;
    std::string Internetl;
    std::string Transportl;
    std::string Applicationl;
    ether_header *myeth;
    std::string Smacaddr;
    std::string Dmacaddr;
    std::string Sadder;
    std::string Dadder;
    int sport;
    int dport;
    std::string msg;
    int size;
    char *data;
    bool DF;
    uint16_t fragoffset;
    bool  MF;

    myip(Ui::myip* other) {
        // Copy or initialize members based on the 'other' instance
        Linkl = other->Linkl;
        Internetl = other->Internetl;
        Transportl = other->Transportl;
        Applicationl = other->Applicationl;
        myeth = other->myeth;
        Smacaddr = other->Smacaddr;
        Dmacaddr = other->Dmacaddr;
        Sadder = other->Sadder;
        Dadder = other->Dadder;
        sport = other->sport;
        dport = other->dport;
        msg = other->msg;
        size = other->size;
        // Dynamically allocate memory for 'data' if needed
        DF = other->DF;
    }
    ~myip() {
        // No need to explicitly release Pname, std::unique_ptr will handle it.

        // Release any other dynamically allocated resources if needed
    }

}myip;

class packetd;
}

class packetd : public QMainWindow
{

    Q_OBJECT

public:
    explicit packetd(QWidget *parent = nullptr,Ui::myip *f=nullptr);
    ~packetd();

private:
    Ui::packetd *ui;
};

#endif // PACKETD_H
