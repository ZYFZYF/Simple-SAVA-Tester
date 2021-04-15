# Simple-SAVA-Tester

本项目用于清华校园网IPv6源地址验证部署情况测试。

## Client运行方法（For windows）

 - 在python3.6.8下运行成功（不保证更高版本或更低版本不存在兼容问题）
 - 在https://nmap.org/npcap/#download 安装npcap
 - 执行 pip install -r requirements.txt 之后以管理员权限执行 python3 client.py即可

## Client运行方法（For mac/linux）
 - 在python3.6.8下运行成功（不保证更高版本或更低版本不存在兼容问题）
 - 执行 pip install -r requirements.txt 之后执行 sudo python3 client.py即可
 
## 一些额外说明
 - 整个过程可能会持续几分钟（也可能很快）
 - 输出 所有测试结束 说明测试完成
 
## 可能出现的问题
 - 无法连接Tsinghua-IPv6-SAVA或连接后无法登录bt.byr.cn
    - 如果是2020级新生，需要在usereg里进行SAVI注册和手机号绑定
    - 否则需确保WPA2认证通过（即连接wifi时弹出来的账号密码，不是网页端net.tsinghua.edu.cn的认证）
        - 注意该密码与Tsinghua-Secure密码相同，并未随《2021年度电子身份年审工作》中修改的info密码一同修改
        - 如果之前已经用错误密码连接，并且没有自动提示输入新的密码，那么可以忘记该WIFI，下次再连接就可重新输入
 - 运行程序没反应
    - 使用powershell:建议用cmd或者pycharm里运行
    - 开启代理:关闭代理后再次运行
    - 连接有线网络:把有线网禁用后再次运行
 
 