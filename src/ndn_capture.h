#ifndef NDN_CAPTURE_H_
#define NDN_CAPTURE_H_

#include <string>
#include <memory>
#include <queue>
#include <mutex>

#include <sys/socket.h>

#include <boost/asio.hpp>

#include <ndn-cxx/util/scheduler.hpp>

#include "consumer/ndn_consumer.h"

class Capture{
public:
    Capture(std::map<std::string, std::string> & neighborStore);

    ~Capture();

    void run();

    void setCacheFlag(bool);

    int getPktFromQue(std::string &);

private:
    bool handlePacket(size_t len, const uint8_t * pkt);

    bool handleNdN(size_t len, const uint8_t * pkt);

    void getMacAddr(const std::string & interface, uint8_t * addr);

    const char * getInterfaceName(const uint8_t *);

    bool isSent(const uint8_t *);

    bool isEqual(const uint8_t *, const uint8_t *);

    void startTimer(std::string, u_int64_t dura);

private:
    struct Interface{
        uint8_t addr[6];
        std::string neighborName;
        bool trafficState = false;
        std::mutex trafficMutex;
    };

private:
    int m_socket;
    std::string m_pktInfor;
    std::map<std::string, std::unique_ptr<Interface>> m_interfaceStore;
    
    std::mutex m_cacheMutex;
    std::mutex m_pktQueMutex;
    bool m_cacheFlag;
    std::queue<std::string> m_pktQue;
};

#endif