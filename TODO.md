# Simple-SAVA-Tester

## 想法
 - 能不能在路径上用client对某个路由器模拟TCP三次握手，在即将要完成的时候把让server伪造client来发最后一个包，然后client用某种行为来验证与路由器的tcp连接已经被建立了
    - 要么是重新发送这个包，看那边会回复什么？
    - 要么是直接来close掉这个连接
 - 不用那么麻烦，ping包的reply包是真实的，所以直接用伪造源地址ping那台设备就可以看看这台设备有没有收到这个包了
 
## TODO
 - traceroute的时候有空缺的跳数似乎？
    - ![traceroute](traceroute.png)
 - server只负责保存活跃的client，不再负责下发具体的测试任务
    - client新启动后依次运行以下测试
        - 正常发UDP包
        - 伪造各种测试向server发包测试其是否收到
        - 伪造server对若干个固定地址 + traceroute上的地址 进行溯源
        - 发现其他client，对其他client依次进行
            - 正常发UDP包
            - 伪造各种测试向client发包测试是否收到
            - 伪造对端client对若干个固定地址 + traceroute上的地址 进行溯源
        - 然后对端反过来对client也做相应的事情
 - 其他要考虑的就是部署client情况了
 - 控制信息似乎应该用TCP发送（UDP要是丢了就GG）
    - TCP的话应该有队列机制，recv会拿到上一个接收到的包
 - 结果提交给SERVER，以及最终结果的入库
 - 网络问题中，最头大的其实是我这边开始发包，你那边还没开始接受怎么办？（即使sniff就在发包的上一句，但是sniff需要准备时间）
    - trival的解决方案，每次send的时候等一段时间，假定在这段时间内，对方已经准备好sniff
    - 关键在于：如何保证在对方开始sniff的时候再开始send？（如果是sniff准备好了发一个ready包，那么问题来了，你又怎么保证你能收到这个ready包？）
    - 另一个解决方法：READY包总是发在一个固定端口，然后共享一个变量或者用事件类似的东西
 - 重构代码
 - 代码改成多线程（可同时与多个client通信）
 - 不用特定的端口调用pkt.payload会出现问题...
 - 有时候伪造mac包的时候自己突然会断网，然后ip地址会发生改变
 - 路由器上似乎禁止了traceroute?
 - 其实没必要存数据库啊，直接放到csv文件里也行啊（但数据库是为了过滤）
 - sniff需要选择过滤的网卡，sudo yum install gcc python3-devel 安装psutil需要安装这个
 - TCP Socket会把两次的数据接在一起... 黏包
 
## 进度
 - 测试的上限花费是等待时间*测试个数
 
## 2020-11-29
 - windows上可以traceroute到好多路径但是没有测
    - 各个系统默认的traceroute方法不同，windows是icmp，mac/linux是udp，而程序里的traceroute是tcp
    - 解决方法：三种方法都来，取个最长的（直接用ICMP了）
 - mac上client开的tcp连接 windows去连会超时
    - 反过来mac去连windows直接报错unreachable
    - 猜测是因为连接同一个AP，做了隔离？
 - windows上发正常包1个也收不到

## 2020-12-01
 - 现在41:23这台机子上也出现了bug，有很小的概率能跑起来server，否则每次报的错都不一样
 - 3505 SAVA这个是FIT1-211的结果
 - Tsinghua-IPv6-SAVA有点难连...
    - windows上连了发不出去包
    - mac得连好多次
    
## 2020-12-03
 - 为什么SAVA的src_mac都是0呢
 - windows上为啥Tsinghua-Secure发的正常包100个一个都收不到呢
 - 存储信息上加入对端SSID和双方OS
 - MAC断网问题
    - 第一个数字得是4的倍数
 - IPV6下的arp叫ndp
 - 一项任务可以起一个sniff之后整体返回一个结果，就不用等太久

## 2020-12-07
 - 现在这个情况有点复杂...ndp表过于可怕
 - Tsinghua-Secure下的源地址过滤和佳兴测出了一样的结果
 - 现在这个发包的速度不稳定，有的发1秒结束，有的要发14秒，还有的甚至要发24秒，这让我都不知道该等多久了，要不改成结束之后发个信号给对方？

## 2020-12-08
 - 现在SAVA下MAC似乎没过滤，等待一段时间后包就能发过去
 
## 2020-12-12
 - TCP一次不能发太大的包？否则会收不到？
 
## 2020-12-16
 - vlan port? 每次连接到不同的port上？
 
## 2020-12-18
 - mac电脑mac伪造过滤不掉的问题好像在fit楼 H3C这套方案也会出现？
 
## 2020-12-21
 - ssid设成open，路由器
 - wireshark 混杂模式
 - 802.1x
 
 - 抓不到混杂模式的报文（某些苹果电脑）
    - 需要windows买网卡 或者 其他能抓混杂模式的苹果电脑
 - 初始是:: 目的是f0 :: 12啥的
 - yarrp可以traceroute啥的？
 
## 2020-12-23
 - 伪造内网地址是无法过滤的？（贾明麟组测试的结果）
 
## 2021-03-31
 - 通过断开wifi可以修改mac地址，然后再连接，这样本地获得的mac地址也是修改后的（可是这之后的发包算伪造源地址嘛）
 - 其实直接改也能改，改完之后wifi会直接断，但是再次重连不是又绑定上了嘛

## 2021-04-02
 - 内网IP其实没必要去测试，因为本身内网一步到达，没人来过滤，没有意义？检测到内网地址是不会做源地址验证的过滤的？
 - 服务端发包特别慢，这边发1秒的，对面要20秒左右 
## 2021-04-03
 - windows下上传文件老是出问题，log文件无法完整上传
 - 怎么有的windows电脑抓不到ping包呢
 
## 2021-04-09
 - 统计结果数据
    - select os,ssid,count(distinct src_ip) as location_count,count(*) as test_cnt,avg(recv_spoof_num) as recv_spoof_num from IP_in_UDP group by os,ssid;
    - select os,ssid,count(distinct src_mac) as location_count,count(*) as test_cnt,avg(recv_spoof_num) as recv_spoof_num from MAC_in_UDP group by os,ssid; 
 - dq师兄的测试结果没有入库，只能从log里分析了
 - 我的win测一下，ws师兄测一下       
 - 问题：伪造mac 100个包收不全 
 - log传输的也是有问题，有的log只收到一半
 - zy师兄这边python client.py不出东西
 
## 2021-04-12
 - 连接问题已修复，dhcpv6服务器的问题，分配不到地址（慢查询的问题？）
 - mac和windows连接Tsinghua-Secure所需要的步骤不一样么？
    - 前者是旧密码，且不需要每次认证
    - 后者是新密码，需要每次网页认证
    - 和802.1x什么关系
    - 我在阿里mac上也是每次都得网页认证，并且密码是新密码
 - 实测WPA2认证可以保证不需要每次网页认证，并且密码是独立于学号的
 - test-savi-ipv6的频道会自己切换，神奇...
 - 2013AJ9654(A1398)的结果和2019AJ3996(A2159)的结果基本一致，不过更加干净（全都是未伪造成功的udp报文）

## 2021-04-15
 - 如何获取地理位置信息？
    - 调用外界api？花钱、不一定支持ipv6、粗粒度
    - 根据前缀？这个靠谱么？
 - 需不需要考虑打包成exe，对于windows来讲？那mac和linux能保证我机子上打包出来能够在所有版本上运行嘛？