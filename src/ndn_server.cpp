#include "ndn_server.h"
#include "threadpool.h"
#include <iostream>
#include <pcap/pcap.h>

#define ALL_CONTENT_LENGTH 1024*15
#define DATA_MAX_LENGTH 1024

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
    std::string clientRequest = interestName.at(-1).toUri(); //最后一部分表示客户端的请求
    if(clientRequest == "status"){
        m_pool->enqueue([this, interestName]{
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
        m_pool->enqueue([this, interestName]{
            getRunningNetworkDevs();
            
            std::string devList("<Devices>");
            for(auto & item : m_devStore){
                devList.append("<device>" + item.first + "</device>");
                m_pool->enqueue([&item]{
                    item.second->run();
                });
            }
            devList.append("</Devices>");

            sendData(interestName, devList);
        });
    }
    else if(clientRequest == "capture-stop"){
        m_pool->enqueue([this, interestName]{
            for(auto & item : m_devStore){
                item.second->stop();
                item.second.reset();
            }
            m_devStore.clear();

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
            m_pool->enqueue([this, interestName]{
                std::string dataContent("<packets>");
                size_t pre_size;
                do{
                    pre_size = dataContent.size();
                    for(auto &item : m_devStore){
                        item.second->m_mutex.lock();
                        if(!item.second->m_pktQue.empty()){
                            std::string packet = item.second->m_pktQue.front();
                            if(packet.size() < (DATA_MAX_LENGTH-dataContent.size())){
                                dataContent.append(packet);
                                item.second->m_pktQue.pop();
                            }
                            else{
                                item.second->m_mutex.unlock();
                                goto sendData;
                            }
                        }
                        item.second->m_mutex.unlock();
                    }
                }while(dataContent.size() != pre_size);

                sendData:
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

void Server::getRunningNetworkDevs(){
    char errbuf[PCAP_ERRBUF_SIZE]; 

    pcap_if_t * alldevs;
    int ret = pcap_findalldevs(&alldevs, errbuf);
    if(ret < 0){
        std::cerr << "pacp fail to find devs: " << errbuf << std::endl;
    }

    pcap_if_t * dev;
    for(dev = alldevs; dev != NULL; dev = dev->next){
        if(dev->flags == 6 && (strcmp(dev->name, "any") != 0)){
            std::string devName(dev->name);
            auto capture = std::make_unique<Capture>(devName);
            m_devStore.insert({devName, std::move(capture)});
        }
    }
}
