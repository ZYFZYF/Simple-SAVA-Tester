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