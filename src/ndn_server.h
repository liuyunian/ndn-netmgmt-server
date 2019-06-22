#ifndef NDN_SERVER_H_
#define NDN_SERVER_H_

#include <ndn-cxx/face.hpp> //include name.hpp interest.hpp interest-filter.hpp
#include <ndn-cxx/util/time.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <memory>
#include <queue>
#include <mutex>

#include "threadpool.h"
#include "ndn_pacp.h"

class Server{
public:
    Server(const std::string & prefix);

    void run();

private: 
    // @brief 注册接收到Interest包之后的回调函数
    void onInterest(const ndn::Interest & interest);

    // @brief 注册前缀失败之后的回调函数
    void onRegisterFailed(const ndn::Name & prefix, const std::string & reason);

    void sendAck(const ndn::Name & dataName);

    /**
     * @brief 创建Data包并发送
     * @param dataName,Data名称, dataContent,Data包内容
    */
    void sendData(const ndn::Name & dataName, const std::string & dataContent);

    /**
     * @brief 利用nfdc status report xml命令，获取nfd全部状态信息，信息的格式是xml
     * @param statusInfor字符指针,指向的内存区域用于存放nfd状态信息
     * @return 失败返回-1，成功返回０
    */
    int getNFDInformation(char * statusInfor);

    /**
     * @brief 对nfd状态信息进行分段，并包装成data
     * ＠return 返回data包的个数
    */
    size_t paddingStatusDataStore();

    /**
     * @brief 获取正在运行的网络设备
    */
    void getRunningNetworkDevs();

private:
    ndn::Face m_face;
    ndn::KeyChain m_keyChain;

    std::string m_prefix;
    std::unique_ptr<ThreadPool> m_pool = std::make_unique<ThreadPool>(10);

    std::vector<std::unique_ptr<ndn::Data>> m_statusDataStore;

    std::map<std::string, std::unique_ptr<Capture>> m_devStore;
};

#endif

