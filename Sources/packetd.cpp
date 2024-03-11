#include "Headers/packetd.h"


packetd::packetd(QWidget *parent,Ui::myip *fs) :
    QMainWindow(parent),
    ui(new Ui::packetd)
{
    ui->setupUi(this);
    QTreeWidget *treeWidget = ui->treeWidget;
    QList<QTreeWidgetItem*> items = treeWidget->findItems("ewr", Qt::MatchExactly);

    if (!items.isEmpty()) {

        QTreeWidgetItem* itemToModify = items.at(0);
        itemToModify->setText(0,"Link Protocol: " +QString::fromStdString(fs->Linkl)+" ,Source MAC: "+QString::fromStdString(fs->Smacaddr)+" ,Destanion MAC: "+QString::fromStdString(fs->Dmacaddr));

        itemToModify = items.at(1);
        if(fs->Internetl!="ARP"){
            itemToModify->setText(0,"Internet Protocol: " +QString::fromStdString(fs->Internetl)+" ,Source IP: "+QString::fromStdString(fs->Sadder)+" ,Destanion IP: "+QString::fromStdString(fs->Dadder));
        }else{

            itemToModify->setText(0,"Protocol: "+ QString::fromStdString(fs->Internetl)+" ,Source MAC: "+QString::fromStdString(fs->Sadder)+" ,Destanion IP: "+QString::fromStdString(fs->Dadder));
        }

        if(fs->Transportl=="tcp"){

            tcphdr *tcph = (struct tcphdr *) fs->data;
                itemToModify = items.at(2);
                QTreeWidgetItem *treeWidget1 = new QTreeWidgetItem();
                treeWidget1->setText(0," Ack Number: " + QString::fromStdString(std::to_string(tcph->ack_seq)) + ", Seq Number: " + QString::fromStdString(std::to_string(tcph->seq))
                                            +", Ack: "+ QString::fromStdString(std::to_string(tcph->ack)));
                itemToModify->setText(0,"Transort Protocol: "+ QString::fromStdString(fs->Transportl)+" , Source Port: "+QString::number(fs->sport)+" ,Destanion Port: "+QString::number(fs->dport));
                itemToModify->addChild(treeWidget1);


        }else{

            itemToModify->setText(0,"Transport Protocol: " +QString::fromStdString(fs->Transportl)+" ,Source Port: "+QString::number(fs->sport)+" ,Destanion Port: "+QString::number(fs->sport));

        }

    }


}

packetd::~packetd()
{
    delete ui;
}
