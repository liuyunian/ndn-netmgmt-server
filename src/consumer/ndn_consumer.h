#ifndef NDN_CONSUMER_H
#define NDN_CONSUMER_H

#include <string>
#include <ndn-cxx/face.hpp>

class Consumer{
public:
    Consumer(const std::string & name);

    void notifyTopologyChange(const std::string & neighborName, const std::string & status);
    void notifyTrafficChange(const std::string & neighborName, uint64_t seq);

private:
    void sendInterest(ndn::Name & interestName);

    void onData(const ndn::Data &data);
    void onNack(const ndn::Interest & interest);
    void onTimeOut(const ndn::Interest & interest);

private:
    ndn::Face m_face;
    std::string m_name;
    std::string m_prefix = "netmgmt/client";
};

#endif