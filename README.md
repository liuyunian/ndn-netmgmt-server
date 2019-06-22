# ndn-netmgmt-server
NDN网络管理server端程序

#### 目录结构
```
ndn-netmgmt-server 
    -| src 
        -| consumer
            -| ndn_consumer.cpp
            -| ndn_cousumer.h
        -| main.cpp
        -| ndn-capture.cpp
        -| ndn-capture.h
        -| ndn_server.cpp
        -| ndn_server.h
        -| threadpool.h
    -| .gitignore
    -| neighbor.txt
    -| README.md
    -| waf
    -| wscript
``` 

#### 使用方法
依赖
* ndn-cxx 
* libpcap

编译
```
./waf configure
./waf
```

运行
```
build/server -h 查看Usage
```

neighbor.txt中记录的是运行该server端程序节点的名称和每个网口对应的邻居信息
```
/*neighbor.txt*/
NodeName
InterfaceName_1 NeighborName_1
...
IInterfaceName_n NeighborName_n
```