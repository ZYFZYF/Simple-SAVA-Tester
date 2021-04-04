# Simple-SAVA-Tester

本项目用于清华校园网IPv6源地址验证部署情况测试。

## Client运行方法（For windows）

 - 所需python >= 3.6.8
 - 在https://nmap.org/npcap/#download 安装npcap
 - 执行 pip install -r requirements.txt 之后以管理员权限执行 python3 client.py即可

## Client运行方法（For mac/linux）
 - 所需python >= 3.6.8
 - 执行 pip install -r requirements.txt 之后执行 sudo python3 client.py即可
 
## 一些额外说明
 - 整个过程可能会持续几分钟（也可能很快）
 - 输出 所有测试结束 说明测试完成
 - 在windows上powershell里运行程序可能会出现问题，建议用cmd或者在pycharm里运行
 