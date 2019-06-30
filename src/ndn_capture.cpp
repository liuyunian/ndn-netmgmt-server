#include <iostream>
#include <chrono>

#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <ndn-cxx/net/ethernet.hpp>
#include <ndn-cxx/lp/packet.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/lp/nack-header.hpp>

#include "ndn_capture.h"
#include "threadpool.h"
#include "log/log.h"

#define TIME 1000

extern Consumer * consumer;
extern ThreadPool threadPool;

Capture::Capture(std::map<std::string, std::string> & neighborStore):
    m_pktInfor(""),
    m_cacheFlag(false)
{
    for(auto & item : neighborStore){
        auto interface = std::make_unique<Interface>();
        interface->neighborName = item.second;
        getMacAddr(item.first, interface->addr);

        m_interfaceStore.insert({item.first, std::move(interface)});
    }
}

Capture::~Capture(){
    close(m_socket);
}

void Capture::run(){
    m_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(m_socket < 0){
        log_fatal(FAT_SYS, "Server fail to create socket");
    }

    log_info("Capture is running");

    uint8_t buffer[ETH_FRAME_LEN];
    size_t len;
    bool shouldSave = false;
    u_int64_t seq;
    while(1){
        len = recvfrom(m_socket, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
        if(len <= ndn::ethernet::HDR_LEN)
            continue;
        
        shouldSave = handlePacket(len, buffer);
        if(shouldSave){
            ++ seq;
            if(seq == UINT64_MAX){
                seq = 0;
            }

            m_pktInfor.append("</body></packet>");
            log_debug("%s", m_pktInfor.c_str());

            size_t start, end;
            start = m_pktInfor.find("<origin>") + 8;
            end = m_pktInfor.find("</origin>");
            std::string origin = m_pktInfor.substr(start, end-start);
            if(origin == "S"){
                start = m_pktInfor.find("<dev>") + 5;
                end = m_pktInfor.find("</dev>");
                std::string interfaceName = m_pktInfor.substr(start, end-start);

                auto iter = m_interfaceStore.find(interfaceName);
                if(iter != m_interfaceStore.end()){
                    iter->second->trafficMutex.lock();
                    bool state = iter->second->trafficState;
                    iter->second->trafficMutex.unlock();
                    if(!state){
                        consumer->notifyTrafficChange(iter->second->neighborName, seq);
                        startTimer(iter->first, TIME);
                    }
                }
            }
            
            m_cacheMutex.lock();
            if(m_cacheFlag){
                m_pktQueMutex.lock();
                m_pktQue.push(m_pktInfor);
                m_pktQueMutex.unlock();
            }
            m_cacheMutex.unlock();
        }
    }
}

void Capture::setCacheFlag(bool flag){
    m_cacheMutex.lock();
    m_cacheFlag = flag;
    m_cacheMutex.unlock();

    if(flag){
        m_pktQueMutex.lock();
        while(!m_pktQue.empty()){
            m_pktQue.pop();
        }
        m_pktQueMutex.unlock();
    }
}

int Capture::getPktFromQue(std::string & pkt){
    m_pktQueMutex.lock();
    if(m_pktQue.empty()){
        m_pktQueMutex.unlock();

        return -1;
    }

    pkt.clear();
    pkt = m_pktQue.front();
    m_pktQue.pop();

    m_pktQueMutex.unlock();
    return 0;
}

bool Capture::handlePacket(size_t len, const uint8_t * pkt){
    auto ether = reinterpret_cast<const ether_header *>(pkt);
    if(ether->ether_type != htons(ndn::ethernet::ETHERTYPE_NDN)){
        return false;
    }

    const uint8_t * destAddr = ether->ether_dhost;
    const uint8_t * srcAddr = ether->ether_shost;

    m_pktInfor.clear();
    if(isSent(srcAddr)){
        const char * interfaceName = getInterfaceName(srcAddr);
        if(interfaceName == nullptr){
            return false;
        }

        m_pktInfor = "<packet><head><dev>" + std::string(interfaceName) + "</dev><origin>S</origin></head><body>";
    }
    else{
        const char * interfaceName = getInterfaceName(destAddr);
        if(interfaceName == nullptr){
            return false;
        }

        m_pktInfor = "<packet><head><dev>" + std::string(interfaceName) + "</dev><origin>R</origin></head><body>";
    }

    struct timeval tv;
    gettimeofday(&tv, NULL); //获取当前的时间
    m_pktInfor.append(ctime(static_cast<const time_t *>(&tv.tv_sec)));
    m_pktInfor.at(m_pktInfor.size()-1) = ',';

    pkt += ndn::ethernet::HDR_LEN; //指针偏移出以太网帧的头部
    len -= ndn::ethernet::HDR_LEN; //长度减少
    m_pktInfor.append(std::to_string(len) + ",");
    
    return handleNdN(len, pkt);
}

bool Capture::handleNdN(size_t len, const uint8_t *pkt){
    bool isOk = false;
    ndn::Block block;
    std::tie(isOk, block) = ndn::Block::fromBuffer(pkt, len);
    if (!isOk){
        log_err(ERR_NSYS, "NDN truncated packet, length = %d", len);
        return false;
    }

    ndn::lp::Packet lpPacket;
    ndn::Block netPacket;

    if (block.type() == ndn::lp::tlv::LpPacket){
        try{
            lpPacket.wireDecode(block);
        }
        catch (const ndn::tlv::Error &e){
            log_err(ERR_NSYS, "Invalid packet: %s", e.what());
            return false;
        }

        ndn::Buffer::const_iterator begin, end;
        if (lpPacket.has<ndn::lp::FragmentField>()){
            std::tie(begin, end) = lpPacket.get<ndn::lp::FragmentField>();
        }
        else{
            log_err(ERR_NSYS, "Don't have fragmentField");
            return false;
        }

        bool isOk = false;
        std::tie(isOk, netPacket) = ndn::Block::fromBuffer(&*begin, std::distance(begin, end));
        if (!isOk){
            log_err(ERR_NSYS, "NDN packet is fragmented");
            return false;
        }
    }
    else{
        netPacket = std::move(block);
    }

    try{
        switch (netPacket.type()){
            case ndn::tlv::Interest:
            {
                ndn::Interest interest(netPacket);
                ndn::Name interestName = interest.getName();

                // 过滤网管Interest
                for(auto iter = interestName.begin(); iter != interestName.end(); ++ iter){
                    if(iter->toUri() == "netmgmt"){
                        return false;
                    }
                }

                if (lpPacket.has<ndn::lp::NackField>()){
                    ndn::lp::Nack nack(interest);
                    nack.setHeader(lpPacket.get<ndn::lp::NackField>());
                    std::string reason;
                    switch(nack.getReason()){
                        case ndn::lp::NackReason::CONGESTION:
                            reason = "Congestion";
                            break;
                        case ndn::lp::NackReason::DUPLICATE:
                            reason = "Duplicate";
                            break;
                        case ndn::lp::NackReason::NO_ROUTE:
                            reason = "NoRoute";
                            break;
                        default:
                            reason = "None";
                            break;
                    }
                    m_pktInfor.append("NACK,(" + reason + ")" + interestName.toUri());
                }
                else{
                    m_pktInfor.append("INTEREST," + interestName.toUri());
                }

                return true;
                break;
            }
            case ndn::tlv::Data:
            {
                ndn::Data data(netPacket);
                ndn::Name dataName = data.getName();

                // 过滤网管Data
                for(auto iter = dataName.begin(); iter != dataName.end(); ++ iter){
                    if(iter->toUri() == "netmgmt"){
                        return false;
                    }
                }

                m_pktInfor.append("DATA," + data.getName().toUri());

                return true;
                break;
                
            }
            default:
            {
                log_err(ERR_NSYS, "Unsupported NDN packet type %d", netPacket.type());

                return false;
                break;
            }
        }
    }
    catch (const ndn::tlv::Error &e){
        log_err(ERR_NSYS, "Invalid NDN packet: %s", e.what());
        return false;
    }
}

void Capture::getMacAddr(const std::string & interface, uint8_t * addr){
    int sd = socket(AF_INET,SOCK_STREAM,0);
    if(sd < 0){
        log_fatal(FAT_SYS, "Fail to create socket in getMacAddr");
    }
    
    struct ifreq ifreq;
    strncpy(ifreq.ifr_name, interface.c_str(), IFNAMSIZ);
    int err = ioctl(sd, SIOCGIFHWADDR, &ifreq);
    if(err){
        log_fatal(FAT_SYS, "Fail to get Mac addr by ioctl");
    }

    for(int i = 0; i < 6; i++){
        addr[i] = static_cast<u_int8_t>(ifreq.ifr_hwaddr.sa_data[i]);
    }
}

const char * Capture::getInterfaceName(const uint8_t * addr){
    for(auto & item : m_interfaceStore){
        if(isEqual(addr, item.second->addr)){
            return item.first.c_str();
        }
    }
    return nullptr;
}

bool Capture::isSent(const uint8_t * srcAddr){
    for(auto & item : m_interfaceStore){
        if(isEqual(srcAddr, item.second->addr)){
            return true;
        }
    }
    return false;
}

bool Capture::isEqual(const uint8_t * addr1, const uint8_t * addr2){
    assert(addr1 != nullptr && addr2 != nullptr);

    for(int i = 0; i < 6; i++){
        if(addr1[i] != addr2[i]){
            return false;
        }
    }
    return true;
}

void Capture::startTimer(std::string interfaceName, u_int64_t dura){
    threadPool.enqueue([=]{
        auto iter = m_interfaceStore.find(interfaceName);
        if(iter == m_interfaceStore.end()){
            return;
        }

        iter->second->trafficMutex.lock();
        iter->second->trafficState = true;
        iter->second->trafficMutex.unlock();

        std::this_thread::sleep_for(std::chrono::milliseconds(dura));

        iter->second->trafficMutex.lock();
        iter->second->trafficState = false;
        iter->second->trafficMutex.unlock();
    });
}
