#ifndef NDN_PACP_H_
#define NDN_PACP_H_

#include <string>
#include <memory>
#include <queue>
#include <mutex>
#include <pcap/pcap.h>

class Capture{
public:
    Capture(std::string & interface);

    ~Capture();

    void run();

    void stop();

private:
    void handlePacket(const pcap_pkthdr *pkthdr, const uint8_t *payload) const;
    bool handleEther(const uint8_t *pkt, size_t len) const;
    bool handleNdn(const uint8_t *pkt, size_t len) const;

    void getMacAddr();
    bool isSent(const uint8_t * sourceAddr) const;

private:
    std::string m_interface;
    pcap_t * m_pcap;
    int m_dataLinkType; // 数据链路的类型,比如以太网,无线局域网

    uint8_t m_macAddr[6];
    mutable std::string m_pktInfor;

public:
    mutable std::queue<std::string> m_pktQue;
    mutable std::mutex m_mutex;
};

#endif