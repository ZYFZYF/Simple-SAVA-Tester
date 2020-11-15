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