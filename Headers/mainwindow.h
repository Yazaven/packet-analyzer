#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "qboxlayout.h"
#include "packetd.h"
#include <QTableWidgetItem>
#include <QTableWidget>
#include "./ui_mainwindow.h"
#include "snifed.h"
#include <QResizeEvent> 
#include "./ui_mainwindow.h"
#include <QTableWidget>
#include "snifed.h"
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <vector>
#include <pthread.h>

QT_BEGIN_NAMESPACE
namespace Ui {


class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    Ui::myip *k;
    std::vector<Ui::myip*> ipvector;

protected:
    void resizeEvent(QResizeEvent *event) override;


private slots:
    void on_lineEdit_returnPressed();
    void on_tableWidget_itemDoubleClicked(QTableWidgetItem *item);

private:
    Ui::MainWindow *ui;
    packetd *pdetails;
    QVBoxLayout *layout;

};
#endif 

