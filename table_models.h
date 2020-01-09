#pragma once

#include <QAbstractTableModel>
#include <QString>
#include "packet_statistics.h"

using namespace pol4b;

class MacEndpointsModel : public QAbstractTableModel {
   QList<Mac> m_key;
   QList<PacketInfo> m_data;
public:
   MacEndpointsModel(QObject * parent = {}) : QAbstractTableModel{parent} {}
   int rowCount(const QModelIndex &) const override { return m_data.count(); }
   int columnCount(const QModelIndex &) const override { return 7; }
   QVariant data(const QModelIndex &index, int role) const override {
      if (role != Qt::DisplayRole && role != Qt::EditRole) return {};
      const auto &packet_info = m_data[index.row()];
      switch (index.column()) {
      case 0: return QString::fromStdString(m_key[index.row()].to_string());
      case 1: return QString::number(packet_info.tx_packets + packet_info.rx_packets);
      case 2: return QString::number(packet_info.tx_size + packet_info.rx_size);
      case 3: return QString::number(packet_info.tx_packets);
      case 4: return QString::number(packet_info.tx_size);
      case 5: return QString::number(packet_info.rx_packets);
      case 6: return QString::number(packet_info.rx_size);
      default: return {};
      };
   }
   QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
      if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
      switch (section) {
      case 0: return "MAC Address";
      case 1: return "Packets";
      case 2: return "Bytes";
      case 3: return "Tx Packets";
      case 4: return "Tx Bytes";
      case 5: return "Rx Packets";
      case 6: return "Rx Bytes";
      default: return {};
      }
   }
   void append(const Mac &mac, const PacketInfo &packet_info) {
      beginInsertRows({}, m_data.count(), m_data.count());
      m_key.append(mac);
      m_data.append(packet_info);
      endInsertRows();
   }
};

class MacConversationsModel : public QAbstractTableModel {
   QList<MacPair> m_key;
   QList<PacketInfo> m_data;
public:
   MacConversationsModel(QObject * parent = {}) : QAbstractTableModel{parent} {}
   int rowCount(const QModelIndex &) const override { return m_data.count(); }
   int columnCount(const QModelIndex &) const override { return 8; }
   QVariant data(const QModelIndex &index, int role) const override {
      if (role != Qt::DisplayRole && role != Qt::EditRole) return {};
      const auto &packet_info = m_data[index.row()];
      switch (index.column()) {
      case 0: return QString::fromStdString(m_key[index.row()].src_mac.to_string());
      case 1: return QString::fromStdString(m_key[index.row()].dst_mac.to_string());
      case 2: return QString::number(packet_info.tx_packets + packet_info.rx_packets);
      case 3: return QString::number(packet_info.tx_size + packet_info.rx_size);
      case 4: return QString::number(packet_info.tx_packets);
      case 5: return QString::number(packet_info.tx_size);
      case 6: return QString::number(packet_info.rx_packets);
      case 7: return QString::number(packet_info.rx_size);
      default: return {};
      };
   }
   QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
      if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
      switch (section) {
      case 0: return "MAC Address A";
      case 1: return "MAC Address B";
      case 2: return "Packets";
      case 3: return "Bytes";
      case 4: return "Packets A → B";
      case 5: return "Bytes A → B";
      case 6: return "Packets B → A";
      case 7: return "Bytes B → A";
      default: return {};
      }
   }
   void append(const MacPair &mac_pair, const PacketInfo &packet_info) {
      beginInsertRows({}, m_data.count(), m_data.count());
      m_key.append(mac_pair);
      m_data.append(packet_info);
      endInsertRows();
   }
};

class IpEndpointsModel : public QAbstractTableModel {
   QList<Ip> m_key;
   QList<PacketInfo> m_data;
public:
   IpEndpointsModel(QObject * parent = {}) : QAbstractTableModel{parent} {}
   int rowCount(const QModelIndex &) const override { return m_data.count(); }
   int columnCount(const QModelIndex &) const override { return 7; }
   QVariant data(const QModelIndex &index, int role) const override {
      if (role != Qt::DisplayRole && role != Qt::EditRole) return {};
      const auto &packet_info = m_data[index.row()];
      switch (index.column()) {
      case 0: return QString::fromStdString(ip_to_string(m_key[index.row()]));
      case 1: return QString::number(packet_info.tx_packets + packet_info.rx_packets);
      case 2: return QString::number(packet_info.tx_size + packet_info.rx_size);
      case 3: return QString::number(packet_info.tx_packets);
      case 4: return QString::number(packet_info.tx_size);
      case 5: return QString::number(packet_info.rx_packets);
      case 6: return QString::number(packet_info.rx_size);
      default: return {};
      };
   }
   QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
      if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
      switch (section) {
      case 0: return "IP Address";
      case 1: return "Packets";
      case 2: return "Bytes";
      case 3: return "Tx Packets";
      case 4: return "Tx Bytes";
      case 5: return "Rx Packets";
      case 6: return "Rx Bytes";
      default: return {};
      }
   }
   void append(const Ip &mac, const PacketInfo &packet_info) {
      beginInsertRows({}, m_data.count(), m_data.count());
      m_key.append(mac);
      m_data.append(packet_info);
      endInsertRows();
   }
};

class IpConversationsModel : public QAbstractTableModel {
   QList<IpPair> m_key;
   QList<PacketInfo> m_data;
public:
   IpConversationsModel(QObject * parent = {}) : QAbstractTableModel{parent} {}
   int rowCount(const QModelIndex &) const override { return m_data.count(); }
   int columnCount(const QModelIndex &) const override { return 8; }
   QVariant data(const QModelIndex &index, int role) const override {
      if (role != Qt::DisplayRole && role != Qt::EditRole) return {};
      const auto &packet_info = m_data[index.row()];
      switch (index.column()) {
      case 0: return QString::fromStdString(ip_to_string(get_src_ip(m_key[index.row()])));
      case 1: return QString::fromStdString(ip_to_string(get_dst_ip(m_key[index.row()])));
      case 2: return QString::number(packet_info.tx_packets + packet_info.rx_packets);
      case 3: return QString::number(packet_info.tx_size + packet_info.rx_size);
      case 4: return QString::number(packet_info.tx_packets);
      case 5: return QString::number(packet_info.tx_size);
      case 6: return QString::number(packet_info.rx_packets);
      case 7: return QString::number(packet_info.rx_size);
      default: return {};
      };
   }
   QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
      if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
      switch (section) {
      case 0: return "IP Address A";
      case 1: return "IP Address B";
      case 2: return "Packets";
      case 3: return "Bytes";
      case 4: return "Packets A → B";
      case 5: return "Bytes A → B";
      case 6: return "Packets B → A";
      case 7: return "Bytes B → A";
      default: return {};
      }
   }
   void append(const IpPair &ip_pair, const PacketInfo &packet_info) {
      beginInsertRows({}, m_data.count(), m_data.count());
      m_key.append(ip_pair);
      m_data.append(packet_info);
      endInsertRows();
   }
};
