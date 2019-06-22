#include <iostream>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ctime>
#include <boost/endian/conversion.hpp>

#include <ndn-cxx/net/ethernet.hpp>
#include <ndn-cxx/lp/packet.hpp>
#include <ndn-cxx/lp/nack.hpp>

#include "ndn_pacp.h"

Capture::Capture(std::string & interface) : 
    m_interface(interface),
    m_pktInfor("")
{
    getMacAddr(); //获取dev对应的Mac地址
}

Capture::~Capture(){
    if(m_pcap){
        pcap_close(m_pcap); 
    }
}

void Capture::run(){
    // 打开设备
    char errbuf[PCAP_ERRBUF_SIZE]; 
    m_pcap = pcap_open_live(m_interface.c_str(), 65535, true, 1000, errbuf);
    if(m_pcap == nullptr){
        std::cerr << "Cannot open interface " << m_interface << ": " << errbuf << std::endl;
    }

    std::string action;
    action = "listening on " + std::string(m_interface);
    m_dataLinkType = pcap_datalink(m_pcap);
    const char *dltName = pcap_datalink_val_to_name(m_dataLinkType);
    const char *dltDesc = pcap_datalink_val_to_description(m_dataLinkType);
    std::string formattedDlt = dltName ? dltName : std::to_string(m_dataLinkType);
    if (dltDesc){
        formattedDlt += "(" + std::string(dltDesc) + ")";
    }
    std::cout << action << ", link-type " << formattedDlt << std::endl;

    // 编译过滤器
    bpf_program program;
    int status = pcap_compile(m_pcap, &program, "(ether proto 0x8624)", 1, PCAP_NETMASK_UNKNOWN);
    if(status < 0){
        std::cerr << "Cannot compile pcap filter (ether proto 0x8624): " << pcap_geterr(m_pcap) << std::endl;
    }

    // 设置过滤器
    status = pcap_setfilter(m_pcap, &program);
    pcap_freecode(&program);
    if(status < 0){
        std::cerr << "Cannot set pcap filter (ether proto 0x8624): " << pcap_geterr(m_pcap) << std::endl;
    }

    // pcap_loop的回调
    auto callback = [](uint8_t *user, const pcap_pkthdr *pkthdr, const uint8_t *payload) {
        reinterpret_cast<const Capture *>(user)->handlePacket(pkthdr, payload);
    };

    //pcap循环抓包
    status = pcap_loop(m_pcap, -1, callback, reinterpret_cast<uint8_t *>(this));
    if (status < 0){
        std::cerr << "pcap_loop error: " << pcap_geterr(m_pcap) << std::endl;
    }
}

void Capture::stop(){
    pcap_breakloop(m_pcap);
    std::cout << "stop to listen on" << m_interface << std::endl;
}

void Capture::handlePacket(const pcap_pkthdr *pkthdr, const uint8_t *payload) const{
    if (pkthdr->caplen == 0){ //捕获包的长度
        std::cerr << "[Invalid header: caplen=0]" << std::endl;
        return;
    }

    if (pkthdr->len == 0){ //包应该的长度
        std::cerr << "[Invalid header: len=0]" << std::endl;
        return;
    }
    else if (pkthdr->len < pkthdr->caplen){
        std::cerr << "[Invalid header: len(" << pkthdr->len
                  << ") < caplen(" << pkthdr->caplen << ")]" << std::endl;
        return;
    }

    m_pktInfor.clear();
    m_pktInfor.append(ctime(static_cast<const time_t *>(&pkthdr->ts.tv_sec)));
    m_pktInfor.at(m_pktInfor.size()-1) = ',';
    m_pktInfor.append(" " + std::to_string(pkthdr->len) + ", ");

    bool shouldSave = false;

    switch(m_dataLinkType){
        case DLT_EN10MB:
            shouldSave = handleEther(payload, pkthdr->len);
            break;
        default:
            std::cerr << "this link type cannot handle" << std::endl;
            return;
    }

    if(shouldSave){
        m_pktInfor.append("</body></packet>");
        // std::cout << m_pktInfor << std::endl;
        m_mutex.lock();
        m_pktQue.push(m_pktInfor);
        m_mutex.unlock();
    }
}

bool Capture::handleEther(const uint8_t *pkt, size_t len) const{    // IEEE 802.3 Ethernet
    if (len < ndn::ethernet::HDR_LEN){
        std::cerr << "Truncated Ethernet frame, length " << len << std::endl;
        return false;
    }

    auto ether = reinterpret_cast<const ether_header *>(pkt);
    if(isSent(ether->ether_shost)){
        m_pktInfor = "<packet><head><dev>" + m_interface + "</dev><origin>S</origin></head><body>" + m_pktInfor;
    }
    else{
        m_pktInfor = "<packet><head><dev>" + m_interface + "</dev><origin>R</origin></head><body>" + m_pktInfor;
    }

    pkt += ndn::ethernet::HDR_LEN; //指针偏移出以太网帧的头部
    len -= ndn::ethernet::HDR_LEN; //长度减少

    if(boost::endian::big_to_native(ether->ether_type) == ndn::ethernet::ETHERTYPE_NDN){
        return handleNdn(pkt, len);
    }
    else{
        std::cerr << "Unsupported this ethertype " << std::endl;
        return false;
    }
}

bool Capture::handleNdn(const uint8_t *pkt, size_t len) const {
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
                    m_pktInfor.append("NACK, " + interestName.toUri());
                }
                else
                {
                    m_pktInfor.append("INTEREST, " + interestName.toUri());
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
                m_pktInfor.append("DATA, " + data.getName().toUri());
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

void Capture::getMacAddr(){
    struct ifreq ifreq;
    int sock = socket(AF_INET,SOCK_STREAM,0);
    strncpy(ifreq.ifr_name, m_interface.c_str(), IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifreq);

    for(int i = 0; i < 6; i++){
        m_macAddr[i] = static_cast<u_int8_t>(ifreq.ifr_hwaddr.sa_data[i]);
    }
}

bool Capture::isSent(const uint8_t * sourceAddr) const{
    for(int i = 0; i < 6; i++){
        if(m_macAddr[i] != sourceAddr[i]){
            return false;
        }
    }
    return true;
}

