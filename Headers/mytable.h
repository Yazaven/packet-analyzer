#ifndef MYTABLE_H
#define MYTABLE_H

#include <QTableWidget>
#include <QWidget>

class mytable : public QWidget
{
    Q_OBJECT
public:
    explicit mytable(QWidget *parent = nullptr);

protected:
    void resizeEvent(QResizeEvent *event) override;

private:
    QTableWidget *tableWidget;
};

#endif // MYTABLE_H
