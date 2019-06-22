#include <iostream>
#include <ndn-cxx/interest.hpp>

#include "ndn_consumer.h"

Consumer::Consumer(const std::string & name) : 
    m_name(name)
{}

void Consumer::notifyTopologyChange(const std::string & neighborName, const std::string & status){
    ndn::Name interestPrefix(m_prefix);
    sendInterest(interestPrefix.append(m_name).append(neighborName).append(status));
    m_face.processEvents();
}

void Consumer::notifyTrafficChange(const std::string & neighborName, uint64_t seq){
    ndn::Name interestPrefix(m_prefix);
    sendInterest(interestPrefix.append(m_name).append(neighborName).appendNumber(seq));
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
    std::cerr << "INFO: Nack: " << interest.getName() << std::endl;
}

void Consumer::onTimeOut(const ndn::Interest & interest){
    std::cerr << "WARNNING: Time out: " << interest.getName() << std::endl;
}

