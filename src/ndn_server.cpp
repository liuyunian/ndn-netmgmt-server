#include <iostream>

#include "ndn_server.h"
#include "ndn_capture.h"
#include "threadpool.h"

#define ALL_CONTENT_LENGTH 1024*50 // 50KB
#define DATA_MAX_LENGTH 1024

extern std::map<std::string, std::string> neighborStore;
extern Capture * capture;
extern ThreadPool threadPool;

Server::Server(const std::string & prefix) : 
    m_prefix(prefix){}

void Server::run(){
    std::cout << "SERVER IS LISTEN: " << m_prefix << std::endl;

    try {
        m_face.setInterestFilter(
            ndn::Name(m_prefix),
            bind(&Server::onInterest, this, _2),
            nullptr,
            bind(&Server::onRegisterFailed, this, _1, _2)
        );

        m_face.processEvents();     
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }    
}

void Server::onInterest(const ndn::Interest & interest){
    ndn::Name interestName = interest.getName();
    std::cout << "reveive interest: " << interestName << std::endl;

    // 路由选择
    std::string clientRequest = interestName.at(-1).toUri();
    if(clientRequest == "status"){
        threadPool.enqueue([this, interestName]{
            size_t data_num = paddingStatusDataStore();
            if(data_num <= 0){
                std::cerr << "fail to padding status data store" << std::endl;
                return;
            }           

            ndn::Data respondData(interestName);
            respondData.setFreshnessPeriod(ndn::time::milliseconds(2000));
            respondData.setContent((const uint8_t *)&data_num, sizeof(size_t));
            m_keyChain.sign(respondData, ndn::signingWithSha256());
            m_face.put(respondData);
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
            std::cerr << "no match route" << std::endl;
        }
    }
}

void Server::onRegisterFailed(const ndn::Name & prefix, const std::string & reason){
    std::cerr << "Prefix = " << prefix << "Registration Failure. Reason = " << reason << std::endl;
}

void Server::sendAck(const ndn::Name & dataName){
    sendData(dataName, "");
}

void Server::sendData(const ndn::Name & dataName, const std::string & dataContent){
    auto data = std::make_unique<ndn::Data>(dataName);
    data->setFreshnessPeriod(ndn::time::milliseconds(2000)); //Data包生存期2s
    data->setContent((const uint8_t *)&dataContent[0], dataContent.size());
    m_keyChain.sign(*data, ndn::signingWithSha256());
    m_face.put(*data);
}

int Server::getNFDInformation(char * statusInfor){
    FILE * ptr = popen("nfdc status report xml", "r"); //文件指针
    if(ptr == NULL){   
        return -1;
    }   
    fgets(statusInfor, ALL_CONTENT_LENGTH, ptr); //将全部的信息都存到临时tmp字符数组中

    pclose(ptr);
    return 0;
}

size_t Server::paddingStatusDataStore(){
    char statusInfor[ALL_CONTENT_LENGTH];
    int ret = getNFDInformation(statusInfor);
    if(ret < 0){
        std::cerr << "fail to get NFD infor" << std::endl;
        return 0;
    }

    size_t data_num = strlen(statusInfor) / DATA_MAX_LENGTH + 1;
    m_statusDataStore.clear();
    for(u_int64_t i = 0; i < data_num-1; ++ i){
        char buffer[DATA_MAX_LENGTH];
        strncpy(buffer, statusInfor+(i*DATA_MAX_LENGTH), DATA_MAX_LENGTH);

        ndn::Name dataName = ndn::Name(m_prefix).append("status").appendNumber(i);
        auto data = std::make_unique<ndn::Data>(dataName);
        data->setFreshnessPeriod(ndn::time::milliseconds(2000));
        data->setContent((const uint8_t *)buffer, DATA_MAX_LENGTH);
        m_keyChain.sign(*data, ndn::signingWithSha256());

        m_statusDataStore.push_back(std::move(data));
    }

    size_t lastData_size = strlen(statusInfor)-(data_num-1)*DATA_MAX_LENGTH;
    char buffer[lastData_size];
    strncpy(buffer, statusInfor+((data_num-1)*DATA_MAX_LENGTH), lastData_size);

    ndn::Name dataName = ndn::Name(m_prefix).append("status").appendNumber(data_num-1);
    auto data = std::make_unique<ndn::Data>(dataName);
    data->setFreshnessPeriod(ndn::time::milliseconds(2000));
    data->setContent((const uint8_t *)buffer, lastData_size);
    m_keyChain.sign(*data, ndn::signingWithSha256());

    m_statusDataStore.push_back(std::move(data));

    if(m_statusDataStore.size() == data_num){
        return data_num;
    }
    else{
        return -1;
    }
}
