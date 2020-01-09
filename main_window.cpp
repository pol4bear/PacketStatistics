#include "main_window.h"
#include "ui_main_window.h"

using namespace std;
using namespace pol4b;

using ps=PacketStatistics;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    packet_statistics = new PacketStatistics(
        [this]() { on_statistics_finished(); },
        [this](int code) { on_statistics_error(code); }
    );
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::show_message_box(QString title, QString message)
{
    QMessageBox message_box(this);
    message_box.setWindowTitle(title);
    message_box.setText(message);
    message_box.exec();
}

void MainWindow::set_enabled(bool state)
{
    ui->le_path->setEnabled(state);
    ui->btn_select->setEnabled(state);
    ui->btn_statistics->setEnabled(state);
}

void MainWindow::on_btn_select_clicked()
{
    QFileDialog file_dialog(this, tr("pcap 파일을 선택하세요."), QDir::homePath(), tr("Packet Capture(*.pcap *.pcapng)"));

    QStringList file_names;

    if (file_dialog.exec())
        file_names = file_dialog.selectedFiles();

    if (file_names.size() > 0) {
        ui->le_path->setText(file_names.first());
        ui->btn_statistics->setEnabled(true);
    }
}

void MainWindow::on_btn_statistics_clicked()
{
    set_enabled(false);

    packet_statistics->do_statistics(ui->le_path->text().toStdString());
}

void MainWindow::on_statistics_finished()
{
    set_enabled(true);

    StatisticsWindow statistics_window(packet_statistics, this);
    statistics_window.exec();
}

void MainWindow::on_statistics_error(int error_code)
{
    set_enabled(true);

    switch(error_code) {
    case ps::ERR_DUP_REQ:
        show_message_box("정보", "이미 분석이 실행중입니다.");
        break;
    case ps::ERR_FILE_NOTFOUND:
        show_message_box("정보", "선택된 파일이 존재하지 않습니다.");
        break;
    case ps::ERR_PCAP_OPEN:
        show_message_box("정보", "선택된 파일이 잘못되었습니다.");
        break;
    }
}
