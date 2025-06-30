#include "Headers/mainwindow.h"
#include "./ui_mainwindow.h"
#include "Headers/snifed.h"
#include <QResizeEvent> 
#include "./ui_mainwindow.h"
#include <QTableWidget>
#include "Headers/snifed.h"



int minport=0;
int ind=0;
int maxport=0;
int prodes=0;
std::string host;

struct ThreadData {
    QTableWidget* tableWidget;
    MainWindow* mainwin;
};


bool isAscii(const std::string& str) {
    for (char c : str) {
        if (static_cast<unsigned char>(c) > 127) {
            return false;
        }
    }
    return true;
}
void* snifferThread(void* data) {

    ThreadData* threadData = static_cast<ThreadData*>(data);
    threadData->tableWidget->setRowCount(10);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {

        return nullptr;
    }
    int size=0;
    char buffer[66999];

    int i=0;
    while (true) {
        memset(buffer,0,sizeof(buffer));
        if(fd>0){
            size=recvfrom(fd,buffer,sizeof(buffer),0,0,0);
            if(size>0){

                std::unique_ptr<Snifed> ptr = std::make_unique<Snifed>(buffer);
                if(ptr->getIPhdr()!=nullptr){
                    std::unique_ptr<Ui::myip> ipData = std::make_unique<Ui::myip>(*ptr->getIPhdr());
                    Ui::myip* myipInstance = new Ui::myip(ptr->getIPhdr());
                    threadData->mainwin->ipvector.push_back(std::move(myipInstance)); 

                    if(!host.empty()){
                        if(isAscii(host) && isAscii(ptr->getIPhdr()->Sadder)){
                        }
                        if(host==ptr->getIPhdr()->Sadder) {
                            threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                            threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                            threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Dadder)));

                            i++;
                            if(10<=i){
                                threadData->tableWidget->setRowCount(i+1);

                            }
                        }
                        continue;
                    }

                    if(minport!=0){
                        switch (ind){
                        case 0:
                            if (minport <= ptr->getIPhdr()->sport && ptr->getIPhdr()->sport <= maxport || minport <= ptr->getIPhdr()->dport && ptr->getIPhdr()->dport <= maxport) {
                                threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                                threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                                threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString(QString::number(ptr->getIPhdr()->sport))));
                                i++;
                                if(10<=i){
                                    threadData->tableWidget->setRowCount(i+1);

                                }
                            }
                            break;

                        case 1:
                            if (minport <= ptr->getIPhdr()->sport && ptr->getIPhdr()->sport <= maxport) {
                                threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                                threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                                threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString(QString::number(ptr->getIPhdr()->sport))));
                                i++;
                                if(10<=i){
                                    threadData->tableWidget->setRowCount(i+1);

                                }
                            }
                            break;
                        case 2:
                            if (minport <= ptr->getIPhdr()->dport <=maxport) {
                                threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                                threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                                threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString(QString::number(ptr->getIPhdr()->dport))));
                                i++;
                                if(10<=i){
                                    threadData->tableWidget->setRowCount(i+1);

                                }
                            }
                            break;

                        case 3:
                            if(("tcp"==ptr->getIPhdr()->Transportl)&&(minport <= ptr->getIPhdr()->sport && ptr->getIPhdr()->sport <= maxport || minport <= ptr->getIPhdr()->dport && ptr->getIPhdr()->dport <= maxport)){
                                threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                                threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                                threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString(QString::number(ptr->getIPhdr()->sport))));
                                i++;
                                if(10<=i){
                                    threadData->tableWidget->setRowCount(i+1);

                                }
                            }
                            break;
                        case 7:
                            if(("udp"==ptr->getIPhdr()->Transportl)&&(minport <= ptr->getIPhdr()->sport && ptr->getIPhdr()->sport <= maxport || minport <= ptr->getIPhdr()->dport && ptr->getIPhdr()->dport <= maxport)){
                                threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                                threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                                threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Dadder)));
                                i++;
                                if(10<=i){
                                    threadData->tableWidget->setRowCount(i+1);

                                }
                            }
                            break;

                        case 4:
                            if((("tcp"==ptr->getIPhdr()->Transportl))&&(minport <= ptr->getIPhdr()->sport && ptr->getIPhdr()->sport <= maxport)){
                                threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                                threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                                threadData->tableWidget->setItem(i, 3, new QTableWidgetItem((QString::number(ptr->getIPhdr()->sport))));
                                i++;
                                if(10<=i){
                                    threadData->tableWidget->setRowCount(i+1);

                                }
                            }
                            break;

                        case 5:
                            if(("tcp"==ptr->getIPhdr()->Transportl)&&(minport <= ptr->getIPhdr()->dport && ptr->getIPhdr()->dport <= maxport)){
                                threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                                threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                                threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString(QString::number(ptr->getIPhdr()->sport))));
                                i++;
                                if(10<=i){
                                    threadData->tableWidget->setRowCount(i+1);

                                }
                            }
                            break;

                        case 8:
                            if(("udp"==ptr->getIPhdr()->Transportl)&&(minport <= ptr->getIPhdr()->sport && ptr->getIPhdr()->sport <= maxport)){
                                threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                                threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                                threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Dadder)));
                                i++;
                                if(10<=i){
                                    threadData->tableWidget->setRowCount(i+1);

                                }
                            }
                            break;

                        case 9:
                            if(("udp"==ptr->getIPhdr()->Transportl)&&(minport <= ptr->getIPhdr()->dport && ptr->getIPhdr()->dport <= maxport)){
                                threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                                threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                                threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Dadder)));
                                i++;
                                if(10<=i){
                                    threadData->tableWidget->setRowCount(i+1);
                                }
                            }
                            break;







                        }
                    }else{
                        threadData->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Transportl)));
                        threadData->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Sadder)));
                        threadData->tableWidget->setItem(i, 3, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->Dadder)));
                        threadData->tableWidget->setItem(i, 4, new QTableWidgetItem(QString::fromStdString(ptr->getIPhdr()->msg)));

                        i++;
                        if(10<=i){
                            threadData->tableWidget->setRowCount(i+1);

                        }


                    }


                }
            }
        }
    }
    close(fd);


    return nullptr;
}



MainWindow::MainWindow(QWidget *parent): QMainWindow(parent)
    , ui(new Ui::MainWindow)
{

    ui->setupUi(this);


    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeMode::Stretch);

    std::vector<std::vector<Ui::myip>> ipvector;
    ThreadData* threadData = new ThreadData;
    threadData->tableWidget = ui->tableWidget;
    threadData->mainwin = this;
    pthread_t thread;
    int result = pthread_create(&thread, nullptr, snifferThread, threadData);

    if (result != 0) {


    }


}

MainWindow::~MainWindow()
{

    delete ui;
}


void MainWindow::resizeEvent(QResizeEvent *event)
{
    ui->lineEdit->setGeometry(10, 0,event->size().width() - 20, 22);
    QMainWindow::resizeEvent(event);

}





std::string applySubnetMask(const std::string& ipAddress, int subnetMask) {
    std::stringstream ss(ipAddress);
    std::string token;
    std::vector<int> ipParts;

    while (std::getline(ss, token, '.')) {
        ipParts.push_back(std::stoi(token));
    }

    for (int i = subnetMask; i < 4; ++i) {
        ipParts[i] = 0;
    }

    std::stringstream result;
    for (int i = 0; i < 4; ++i) {
        result << ipParts[i];
        if (i < 3) {
        result << '.';
        }
    }

    return result.str();
}

std::string getFullIPAddress(const std::string& hostSpec) {
    std::string fullIPAddress;

        std::string hosts = hostSpec.substr(5);

        if (strchr(hosts.c_str(), '.') == nullptr) {
        fullIPAddress = hosts + ".0.0.0";
        } else {
        fullIPAddress = hosts;
        }
     if(hostSpec.find('/') != std::string::npos) {
        std::string ipAddress = hostSpec.substr(0, hostSpec.find('/'));
        int subnetMask = std::stoi(hostSpec.substr(hostSpec.find('/') + 1));
        fullIPAddress = applySubnetMask(ipAddress, subnetMask);
    } else {
        if (strchr(hostSpec.c_str(), '.') == nullptr) {
        fullIPAddress = hostSpec + ".0.0.0";
        } else {
        fullIPAddress = hostSpec;
        }
    }

    return fullIPAddress;
}

void MainWindow::on_lineEdit_returnPressed()
{
    ind=0;
    char ipv4[32];
    char *argv[20];
    int i;
    QString inputText = ui->lineEdit->text();
    QByteArray byteArray = inputText.toUtf8();
    char* charArray = new char[byteArray.size()+1];
    strcpy(charArray, byteArray.constData());
    argv[0] = NULL;
    i = 0;
    char*  token = strtok (charArray," ");
    for (int j = 0; j < 11; j++) {
        argv[j] = NULL;
    }


    while (token!= NULL)
    {
        argv[i] = token;
        token = strtok (NULL, " ");
        i++;
    }
    argv[i] = NULL;
    for (int j = 0; j < i; j++) {
        if(!strncmp(argv[j],"src",3)){
        ind+=1;
        }
        if(!strncmp(argv[j],"dst",3)){
        ind+=2;
        }
        if(!strncmp(argv[j],"tcp",3)){
        ind+=3;
        }
        if(!strncmp(argv[j],"udp",3)){
        ind+=7;
        }



        if(!strncmp(argv[j],"port",4)){
        minport=maxport=(std::atoi(argv[j+1]));
        }
        if(!strncmp(argv[j],"portrange",9)){
        minport=std::atoi(argv[j+1]) ;

        //if(!strncmp(argv[j+2],"-",1)){
        maxport = std::atoi(argv[j+3]) ;
        //}

        }

        if(!strncmp(argv[j],"host",4)){
        std::string strFromCharPtr(charArray);
        host=  getFullIPAddress(argv[j+1]);
        break;

        }

    }




    delete[] charArray;
}



void MainWindow::on_tableWidget_itemDoubleClicked(QTableWidgetItem *item)
{

    pdetails=new packetd(this,ipvector[item->row()]);
    pdetails->show();


}

