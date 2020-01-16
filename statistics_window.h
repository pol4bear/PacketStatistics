#ifndef STATISTICSWINDOW_H
#define STATISTICSWINDOW_H

#include <QDialog>
#include "packet_statistics.h"
#include "table_models.h"

using namespace pol4b;

namespace Ui {
class StatisticsWindow;
}

class StatisticsWindow : public QDialog
{
    Q_OBJECT

public:
    explicit StatisticsWindow(pol4b::PacketStatistics &ps, QWidget *parent = nullptr);
    ~StatisticsWindow();

private:
    Ui::StatisticsWindow *ui;
    PacketStatistics::MacEndpoints *mac_endpoints;
    PacketStatistics::MacConversations *mac_conversations;
    PacketStatistics::IpEndpoints *ip_endpoints;
    PacketStatistics::IpConversations *ip_conversations;
    MacEndpointsModel mac_endpoints_model;
    MacConversationsModel mac_conversations_model;
    IpEndpointsModel ip_endpoints_model;
    IpConversationsModel ip_conversations_model;

    void initialize();
};

#endif // STATISTICSWINDOW_H
