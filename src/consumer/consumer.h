#ifndef CONSUMER_H
#define CONSUMER_H

#include <string>
#include <ndn-cxx/face.hpp>

class Consumer{
public:
    Consumer(const std::string & name, const std::string & prefix);

    void inform(const std::string & neighborName, const std::string & status);

private:
    void sendInterest(ndn::Name & interestName);

    void onData(const ndn::Data &data);
    void onNack(const ndn::Interest & interest);
    void onTimeOut(const ndn::Interest & interest);

private:
    ndn::Face m_face;
    std::string m_nodeName;
    std::string m_prefix;
};

#endif