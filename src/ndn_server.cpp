#include <string.h>
#include <iostream>

#include "ndn_server.h"
#include "ndn_capture.h"
#include "threadpool.h"
#include "log/log.h"

#define ALL_CONTENT_LENGTH 1024*50 // 50KB
#define DATA_MAX_LENGTH 1024

extern std::map<std::string, std::string> neighborStore;
extern Capture * capture;
extern ThreadPool threadPool;

Server::Server(const std::string & prefix) : 
    m_prefix(prefix){}

void Server::run(){
    try {
        m_face.setInterestFilter(
            ndn::Name(m_prefix),
            bind(&Server::onInterest, this, _2),
            nullptr,
            bind(&Server::onRegisterFailed, this, _2)
        );

        log_info("Server is listening %s", m_prefix.c_str());

        m_face.processEvents();
    }
    catch (const std::exception& e) {
        log_fatal(FAT_NSYS, "%s", e.what());
    }    
}

void Server::onInterest(const ndn::Interest & interest){
    ndn::Name interestName = interest.getName();
    log_info("Receive interest: %s", interestName.toUri().c_str());

    // 路由选择
    std::string clientRequest = interestName.at(-1).toUri();
    if(clientRequest == "status"){
        threadPool.enqueue([this, interestName]{
            paddingStatusDataStore();
            if(m_statusDataStore.empty()){
                log_err(ERR_NSYS, "statusDataStore is empty");
            }           

            size_t dataNum = m_statusDataStore.size();
            ndn::Data respondData(interestName);
            respondData.setFreshnessPeriod(ndn::time::milliseconds(2000));
            respondData.setContent((const uint8_t *)&dataNum, sizeof(size_t));
            m_keyChain.sign(respondData, ndn::signingWithSha256());

            m_face.put(respondData);
            log_info("Send Data: %s", interestName.toUri().c_str());
        });
    }
    else if(clientRequest == "capture-start"){
        threadPool.enqueue([this, interestName]{
            std::string devList("<Devices>");
            for(auto & item : neighborStore){
                devList.append("<device>" + item.first + "</device>");
            }
            devList.append("</Devices>");

            capture->setCacheFlag(true);

            sendData(interestName, devList);
        });
    }
    else if(clientRequest == "capture-stop"){
        threadPool.enqueue([this, interestName]{
            capture->setCacheFlag(false);
            sendAck(interestName);
        });
    }
    else{
        clientRequest = interestName.at(-2).toUri();
        if(clientRequest == "status"){
            const auto segmentNo = static_cast<u_int64_t>(interestName.at(-1).toNumber());

            m_face.put(*(m_statusDataStore.at(segmentNo)));
            ndn::Name dataName = m_statusDataStore.at(segmentNo)->getName();
            log_info("Send Data: %s", dataName.toUri().c_str());
        }
        else if(clientRequest == "packet"){
            threadPool.enqueue([this, interestName]{
                std::string dataContent("<packets>");
                std::string packet;
                for(;;){
                    if(capture->getPktFromQue(packet) >= 0 && packet.size() < (DATA_MAX_LENGTH - dataContent.size())){
                        dataContent.append(packet);
                    }
                    else{
                        break;
                    }
                }

                if(dataContent == "<packets>"){
                    sendAck(interestName);
                }
                else{
                    dataContent.append("</packets>");
                    sendData(interestName, dataContent);
                }
            });
        }
        else{
            log_err(ERR_NSYS, "No match route for this client request");
        }
    }
}

void Server::onRegisterFailed(const std::string & reason){
    log_fatal(FAT_NSYS, "Prefix = %s registration failure %s", 
            m_prefix.c_str(), 
            reason.c_str()
    );
}

void Server::sendAck(const ndn::Name & dataName){
    sendData(dataName, "");
}

void Server::sendData(const ndn::Name & dataName, const std::string & dataContent){
    auto data = std::make_unique<ndn::Data>(dataName);
    data->setFreshnessPeriod(ndn::time::milliseconds(2000));
    data->setContent((const uint8_t *)&dataContent[0], dataContent.size());
    m_keyChain.sign(*data, ndn::signingWithSha256());

    m_face.put(*data);
    log_info("Send Data: %s", dataName.toUri().c_str());
}

int Server::getNFDStatus(char * statusInfor){
    FILE * ptr = popen("nfdc status report xml", "r");
    if(ptr == NULL){   
        return -1;
    }   
    fgets(statusInfor, ALL_CONTENT_LENGTH, ptr);
    pclose(ptr);
    return 0;
}

void Server::paddingStatusDataStore(){
    char statusInfor[ALL_CONTENT_LENGTH];
    int ret = getNFDStatus(statusInfor);
    if(ret < 0){
        log_err(ERR_NSYS, "Fail to get NFD status");
        return;
    }

    size_t dataNum = strlen(statusInfor) / DATA_MAX_LENGTH + 1;
    m_statusDataStore.clear();
    char buffer[DATA_MAX_LENGTH + 1] = {0};
    
    for(u_int64_t i = 0; i < dataNum; ++ i){
        strncpy(buffer, statusInfor+(i*DATA_MAX_LENGTH), DATA_MAX_LENGTH);
        log_debug("%d, %s", strlen(buffer), buffer);

        ndn::Name dataName = ndn::Name(m_prefix).append("status").appendNumber(i);
        auto data = std::make_unique<ndn::Data>(dataName);
        data->setFreshnessPeriod(ndn::time::milliseconds(2000));
        data->setContent((const uint8_t *)buffer, strlen(buffer));
        m_keyChain.sign(*data, ndn::signingWithSha256());

        m_statusDataStore.push_back(std::move(data));
    }
}
