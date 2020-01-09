#include "statistics_window.h"
#include "ui_statistics_window.h"

StatisticsWindow::StatisticsWindow(const PacketStatistics *ps, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::StatisticsWindow)
{
    mac_endpoints = ps->get_mac_endpoints();
    mac_conversations = ps->get_mac_conversations();
    ip_endpoints = ps->get_ip_endpoints();
    ip_conversations = ps->get_ip_conversations();

    ui->setupUi(this);
    this->setWindowTitle(QString::fromStdString(ps->get_file_name()));
    initialize();
}

StatisticsWindow::~StatisticsWindow()
{
    delete ui;
}

void StatisticsWindow::initialize()
{
    for (MacEndpoints::const_iterator it = mac_endpoints->begin(); it != mac_endpoints->end(); it++) {
        mac_endpoints_model.append(it->first, it->second);
    }
    ui->tv_mac_1->setModel(&mac_endpoints_model);

    for (MacConversations::const_iterator it = mac_conversations->begin(); it != mac_conversations->end(); it++) {
        mac_conversations_model.append(it->first, it->second);
    }
    ui->tv_mac_2->setModel(&mac_conversations_model);

    for (IpEndpoints::const_iterator it = ip_endpoints->begin(); it != ip_endpoints->end(); it++) {
        ip_endpoints_model.append(it->first, it->second);
    }
    ui->tv_ip_1->setModel(&ip_endpoints_model);

    for (IpConversations::const_iterator it = ip_conversations->begin(); it != ip_conversations->end(); it++) {
        ip_conversations_model.append(it->first, it->second);
    }
    ui->tv_ip_2->setModel(&ip_conversations_model);
}
