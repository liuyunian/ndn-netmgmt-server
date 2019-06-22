#include <iostream>
#include <fstream>
#include <set>
#include <map>

#include <assert.h>
#include <pcap/pcap.h>
#include <boost/program_options.hpp>

#include "ndn_server.h"
#include "ndn_capture.h"
#include "threadpool.h"
#include "consumer/ndn_consumer.h"

ThreadPool threadPool(10); // Thread Pool
Consumer * consumer = nullptr;
Capture * capture = nullptr;
std::map<std::string, std::string> neighborStore;

static std::set<std::string> interfaceSet;

static void
getRunningInterface(){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t * interfaces;

	int ret = pcap_findalldevs(&interfaces, errbuf);
    if(ret < 0){
        std::cerr << "ERROR: Pacp fail to find interfaces: " << errbuf << std::endl;
		exit(1);
    }

	pcap_if_t * interface;
    for(interface = interfaces; interface != NULL; interface = interface->next){
        if(interface->flags == 6 && (strcmp(interface->name, "any") != 0)){
            std::string interfaceName(interface->name);
            interfaceSet.insert(interfaceName);
        }
    }

    pcap_freealldevs(interfaces);
}

static int
listenChangeForInterface(std::string & interfaceName){
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t * interfaces;

	int ret = pcap_findalldevs(&interfaces, errbuf);
    if(ret < 0){
        std::cerr << "WARRNING: Pacp fail to find interfaces: " << errbuf << std::endl;
		return 2;
    }

    pcap_if_t * interface;
	size_t runningInterface_num = 0;
	std::set<std::string> nameSet;
    for(interface = interfaces; interface != NULL; interface = interface->next){
        if(interface->flags == 6 && (strcmp(interface->name, "any") != 0)){
			++ runningInterface_num;
            interfaceName = std::string(interface->name);
			nameSet.insert(interfaceName);

            auto iter = interfaceSet.find(interfaceName);
            if(iter == interfaceSet.end()){
                pcap_freealldevs(interfaces);
                return 1;
            }
        }
    }
	pcap_freealldevs(interfaces);

	if(runningInterface_num < interfaceSet.size()){
		for(auto & item : interfaceSet){
			auto iter = nameSet.find(item);
			if(iter == nameSet.end()){
				interfaceName = item;
				return -1;
			}
		}
	}

    return 0;
}

void listenThreadEntry(){
    while(true){
        std::string interfaceName;
        int ret = listenChangeForInterface(interfaceName);

        if(ret < 0){
            std::cout << "INFO: The interface " << interfaceName << " stopped" << std::endl;
            auto interface_iter = interfaceSet.find(interfaceName);
            interfaceSet.erase(interface_iter);

            auto neighbor_iter = neighborStore.find(interfaceName);
            if(neighbor_iter != neighborStore.end()){
                consumer->notifyTopologyChange(neighbor_iter->second, "stop");
            }
        }
        else if(ret > 0){
            std::cout << "INFO: The interface " << interfaceName << " is running" << std::endl;
            interfaceSet.insert(interfaceName);

            auto neighbor_iter = neighborStore.find(interfaceName);
            if(neighbor_iter != neighborStore.end()){
                consumer->notifyTopologyChange(neighbor_iter->second, "start");
            }
        }
    }
}

void readNeighbor(std::string & nodeName){
    std::string line;
    std::ifstream fin("./neighbor.txt");
    assert(fin.is_open());

    assert(std::getline(fin, line));
    std::stringstream ss(line);
    ss >> nodeName;
    std::cout << nodeName << std::endl;

    std::string interface;
    std::string neighborName;
    while(std::getline(fin, line)){
        std::stringstream ss(line);
        ss >> interface >> neighborName;
        std::cout << interface << std::endl;
        std::cout << neighborName << std::endl;
        neighborStore.insert({interface, neighborName});
    }
}

void usage(const boost::program_options::options_description &options){
    std::cout << "Usage: sudo build/server [options] <prefix>" << std::endl;
    std::cout << options;

    exit(0);
}

int main(int argc, char* argv[]){
    std::string prefix("/localhost");

    namespace po = boost::program_options;
    
    po::options_description visibleOptDesc("Allowed options");
    visibleOptDesc.add_options()("help,h", "print this message and exit")
                                ("prefix,p", po::value<std::string>(), "root prefix");

    po::variables_map optVm;    
    store(parse_command_line(argc, argv, visibleOptDesc), optVm);

    if(optVm.count("help")){
        usage(visibleOptDesc);
    }
    
    if(optVm.count("prefix")){
        prefix = optVm["prefix"].as<std::string>();
    }

    std::string nodeName;
    readNeighbor(nodeName);
    consumer = new Consumer(nodeName);
    
    getRunningInterface();
    std::thread listenThread(listenThreadEntry);

    capture = new Capture(neighborStore);
    std::thread captureThread(&Capture::run, capture);
    
    Server server(prefix.append("/netmgmt"));
    server.run();

    listenThread.join();
    captureThread.join();

    delete consumer;
    delete capture;

    return 0;
}
