#include "mainwindow.h"
#include <QApplication>
#include <QWidget>
#include <pthread.h>


int main(int argc, char *argv[])
{

    // Wait for the thread to finish



    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
