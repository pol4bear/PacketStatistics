#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>
#include "packet_statistics.h"
#include "statistics_window.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_btn_select_clicked();

    void on_btn_statistics_clicked();

private:
    Ui::MainWindow *ui;
    pol4b::PacketStatistics *packet_statistics;

    void show_message_box(QString title, QString message);
    void set_enabled(bool state);

    void on_statistics_finished();
    void on_statistics_error(int error_code);
};
#endif // MAINWINDOW_H
