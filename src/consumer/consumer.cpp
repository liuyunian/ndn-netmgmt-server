#include <iostream>
#include <ndn-cxx/interest.hpp>

#include "consumer/consumer.h"

Consumer::Consumer(const std::string & name, const std::string & prefix):
    m_nodeName(name),
    m_prefix(prefix){}

void Consumer::inform(const std::string & neighborName, const std::string & status){
    ndn::Name interestPrefix(m_prefix);
    sendInterest(interestPrefix.append(m_nodeName).append(neighborName).append(status));
    m_face.processEvents();
}

void Consumer::sendInterest(ndn::Name & interestName){
    ndn::Interest interest(interestName);

    interest.setCanBePrefix(false);
    interest.setMustBeFresh(true);
    interest.setInterestLifetime(ndn::time::milliseconds(4000));
    interest.setNonce(std::rand());

    try {
        m_face.expressInterest(interest,
        std::bind(&Consumer::onData, this, _2), 
        std::bind(&Consumer::onNack, this, _1), 
        std::bind(&Consumer::onTimeOut, this, _1));
        std::cout << "send Interest: " << interest.getName() << std::endl;
    }
    catch (std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
}

void Consumer::onData(const ndn::Data & data){
    std::cout << "INFO: Receive Data: " << data.getName() << std::endl;
}

void Consumer::onNack(const ndn::Interest & interest){
    std::cerr << "Nack: " << interest.getName() << std::endl;
}

void Consumer::onTimeOut(const ndn::Interest & interest){
    std::cerr << "Time out: " << interest.getName() << std::endl;

    // 重传处理
    
}

