#include <iostream>
#include <chrono>

#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <boost/endian/conversion.hpp>
// #include <boost/bind.hpp>

#include <ndn-cxx/net/ethernet.hpp>
#include <ndn-cxx/lp/packet.hpp>
#include <ndn-cxx/lp/nack.hpp>

#include "ndn_capture.h"
#include "threadpool.h"

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
        std::cerr << "ERROR: Server fail to create socket" << std::endl;
        exit(1);
    }

    std::cout << "INFO: Capture is running" << std::endl;

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
            std::cout << m_pktInfor << std::endl;

            ++ seq;
            if(seq == UINT64_MAX){
                seq = 0;
            }

            m_pktInfor.append("</body></packet>");

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
                        startTimer(iter->first, 1000);
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
    if(ether->ether_type != htons(0x8624)){
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
    gettimeofday(&tv, NULL);
    m_pktInfor.append(ctime(static_cast<const time_t *>(&tv.tv_sec)));
    m_pktInfor.at(m_pktInfor.size()-1) = ',';

    pkt += ndn::ethernet::HDR_LEN; //指针偏移出以太网帧的头部
    len -= ndn::ethernet::HDR_LEN; //长度减少
    m_pktInfor.append(std::to_string(len) + ",");

    if(boost::endian::big_to_native(ether->ether_type) == ndn::ethernet::ETHERTYPE_NDN){
        return handleNdN(len, pkt);
    }
    else{
        std::cerr << "Unsupported this ethertype " << std::endl;
        return false;
    }
}

bool Capture::handleNdN(size_t len, const uint8_t *pkt){
    if (len == 0){
        std::cerr << "Invalid NDN packet len = 0" << std::endl;
        return false;
    }

    bool isOk = false;
    ndn::Block block;
    std::tie(isOk, block) = ndn::Block::fromBuffer(pkt, len);
    if (!isOk){
        std::cerr << "NDN truncated packet, length " << len << std::endl;
        return false;
    }

    ndn::lp::Packet lpPacket;
    ndn::Block netPacket;

    if (block.type() == ndn::lp::tlv::LpPacket){
        try{
            lpPacket.wireDecode(block);
        }
        catch (const ndn::tlv::Error &e){
            std::cerr << " invalid packet: " << e.what() << std::endl;
            return false;
        }

        ndn::Buffer::const_iterator begin, end;
        if (lpPacket.has<ndn::lp::FragmentField>()){
            std::tie(begin, end) = lpPacket.get<ndn::lp::FragmentField>();
        }
        else{
            std::cerr << "idle" << std::endl;
            return false;
        }

        bool isOk = false;
        std::tie(isOk, netPacket) = ndn::Block::fromBuffer(&*begin, std::distance(begin, end));
        if (!isOk){
            std::cerr << "NDN packet is fragmented" << std::endl;
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

                for(auto iter = interestName.begin(); iter != interestName.end(); ++ iter){
                    if(iter->toUri() == "netmgmt"){
                        return false;
                    }
                }

                if (lpPacket.has<ndn::lp::NackField>()){
                    m_pktInfor.append("NACK," + interestName.toUri());
                }
                else
                {
                    m_pktInfor.append("INTEREST," + interestName.toUri());
                }
                return true;
                break;
            }
            case ndn::tlv::Data:
            {
                ndn::Data data(netPacket);
                ndn::Name dataName = data.getName();

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
                std::cerr << "Unsupported NDN packet type " << netPacket.type() << std::endl;
                return false;
                break;
            }
        }
    }
    catch (const ndn::tlv::Error &e){
        std::cerr << "invalid network packet: " << e.what() << std::endl;
        return false;
    }
}

void Capture::getMacAddr(const std::string & interface, uint8_t * addr){
    struct ifreq ifreq;
    int sock = socket(AF_INET,SOCK_STREAM,0);
    strncpy(ifreq.ifr_name, interface.c_str(), IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifreq);

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
