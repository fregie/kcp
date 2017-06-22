# GTS
GTS(Geewan Transimit System) provides an new way to transmit you data securely and fast.  
## version: 2.0.0
This version is **kcp** available version,and GTS version is up to 2.0.0  

## 兼容性
服务端兼容 2.0.0 以及 1.x 版本的客户端
客户端配置增加了一个ver字段，连接1.x版本服务端时需将这个字段设置为1，连接2.0.0版本服务端时设置为2  
**注意**：如果不配置合适的mtu效果会很差，建议mtu：出口MTU大小减去92(1500-92=1408)

# 安装
linux：  v

    # install openssl
    yum install openssl-devel

    # install libsodium
    wget https://github.com/jedisct1/libsodium/releases/download/1.0.10/libsodium-1.0.10.tar.gz
    tar xf libsodium-1.0.10.tar.gz && cd libsodium-1.0.10
    ./configure && make -j2 && make install
    echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
    ldconfig

    # git source code and compile
    git clone https://username@github.com/geewan-rd/GTS.git
    cd GTS/ && git checkout develop
    mkdir build && cd build 
    cmake .. && make
    sudo make install

    # if you wish to static link libsodium, run cmake with -DSODIUM_USE_STATIC_LIBRARY=ON
    cmake .. -DSODIUM_USE_STATIC_LIBRARY=ON

    # build with debug info, with -DDEBUG=ON, can combined with SODIUM_USE_STATIC_LIBRARY variable
    cmake .. -DDEBUG=ON

openWRT:  

     cd gopwrt/package/
     git clone https://username@github.com/geewan-rd/GTS.git
     cd gopwrt/
     make PID=GF1 menuconfig    #select GTS in network
     make PID=GF1 package/GTS/compile V=s

## KCP说明
该版本GTS增加了KCP可靠性协议，协议层次如下：  
TUN<-->KCP<-->GTS<-->UDP<---->UDP<-->GTS<-->KCP<-->TUN  

### KCP参数配置
KCP协议需要几个参数，并且需要在双端都配置，为了方便使用，在GTS中我们：在客户端配置参数，客户端的心跳包中会携带KCP的参数信息，服务端开始会采用默认参数，一旦收到心跳包中的参数信息就会根据客户端参数应用合适的参数到服务端的KCP.所以要改变KCP,只需在客户端做出相应修改而不必在服务端做任何事。

## 配置
+ 可以在`/etc/GTS/`下找到配置文件
+ 对于客户端，编辑`client.json`文件
+ 对于服务端，编辑`server.json`文件
+ `client_up.sh`,`server_up.sh`分别为对应程序启动前要执行的脚本
+ `client_down.sh`,`server_down.sh`分别为对应程序结束后要执行的脚本

server.json:

    {
    "server":"0.0.0.0",                         # 服务器ip
    "port":6666,                                # 服务器监听端口
    "header key":"1234ABCE",                    # 用来解密头部信息的key，长度不限，可以使用任意字符
    "token":["ff593b9abeb1","ff593b9abeb2"],    # 用来区分客户端的 6 byte HEX 信息，
                                                  使用命令 xxd -l 8 -p /dev/random 生成
    "password":["geewantest1","geewantest2"],   # 按顺序token对应的密码，长度不限，可以使用任意字符
    "intf":"GTSs_tun",                          # 生成虚拟借口的名称
    "mtu":1408,                                 # 虚拟接口的 MTU, 建议mtu：出口MTU大小减去92(1500-92=1408)
    "net":"10.1.0.1/24",                        # 虚拟借口的ip和子网掩码
    "encrypt":1,                                # 是否对payload部分进行加密（openwrt版本消耗性能较大）
    "shell_up":"/etc/GTS/server_up.sh",         # 启动脚本路径
    "shell_down":"/etc/GTS/server_down.sh",     # 结束脚本路径
    "logfile":"/var/log/GTS-server.log",        # 日志文件路径
    "pidfile":""/var/run/gts.pid""              # pid文件路径
    }

client.json:  
配置大致和server端相同

    {
    "server":"0.0.0.0",                         # 服务端ip
    "port":6666,
    "header_key":"1234ABCE",
    "token":"b88d9ad8eabb",                     # 客户端使用的token
    "password":"geewantest",                    # token对应的密码
    "intf":"GTSc_tun",
    "mtu":1408,
    "net":"10.1.0.2/24",
    "encrypt":1,
    "beat_time":5,                              # 向服务器发送心跳的间隔（秒）
    ################################# KCP参数 ###################################
    "kcp_sndwnd":4096,                          #sndwnd为客户端发送窗口大小，默认4096
    "kcp_rcvwnd":4096,                          #rcvwnd为客户端接收窗口大小，默认4096
    "kcp_nodelay":1,                            #nodelay-启用以后若干常规加速将启动
    "kcp_interval":20,                          #interval为内部处理时钟，默认设置为 20ms
    "kcp_resend":2,                             #resend为快速重传指标，默认设置为2
    "kcp_nc":1,                                 #nc为是否禁用常规流控，这里禁止
    #############################################################################
    "shell_up":"/etc/GTS/client_up.sh",
    "shell_down":"/etc/GTS/client_down.sh",
    "logfile":"/var/log/GTS-client.log",
    "pidfile":""/var/run/gts.pid""
    }

## 运行
服务端：  

    (sudo) GTS-server -c /etc/GTS/server.json [-d {start|stop|restart}]
客户端：  

    (sudo) GTS-server -c /etc/GTS/server.json [-d {start|stop|restart}]

    -c  <config file>    指定配置文件的路径
    -d  <action>         start/stop/restart  以daemon模式运行

## IPC接口
客户端和服务端都提供了 unix domain socket 形式的IPC接口  
支持的信息格式为json

### 服务端  
#### 添加用户  
发送格式：

    {
        "act":"add_user",               # 添加用户
        "token":"b88d9ad8eabb",         # 添加用户的token
        "password":"789632145",         # 添加用户的pasword,长度不限，可以使用任意字符
        "txquota":"1024",               # 允许用户消耗的流量（KB）(-1为无限制)
        "expire":"2016/01/02 12:12:00", # 允许用户在该日期前使用
        "up_limit":512,                 # 对用于进行上行流控(KBps)(-1为无限制)
        "up_burst":1024,                # 允许的上行突发流量(KB)
        "down_limit":512,               # 下行流控(KBps)
        "down_burst":1024               # 下行突发流量(KB)
    }
返回信息：

    {"status":"ok"}
#### 删除用户
发送格式：

    {
        "act":"del_user",               # 删除用户
        "token":"b88d9ad8eabb"          # 要删除用户的token
    }
返回信息：

    {"status":"ok"}
#### 显示状态  
发送格式：

    {"act":"show_stat"}                 # 显示状态
返回信息：
返回所用用户的状态信息

    {
    "status":	"ok",
    "stat":	[{
            "token":    "ff593b9abeb1",
            "txquota":  -1,                 # 用户剩余可用流量
            "tx":	0,                      # 用户消耗的流量
            "rx":	0                       # 用户消耗的流量
        }, {
            "token":	"b88d9ad8eabb",
            "txquota":	1024,
            "expire":	"2016/6/3 14:57:0",
            "tx":	0,
            "rx":	0
        }]
    }


### 客户端
#### 显示状态：
发送格式：

    {"act":"show_stat"}
返回信息：

    {"stat":"2"}
客户端状态代码查询表：

  Code |    stat            
 ------|----------------
   2   | 状态良好         
   3   | header key 错误  
   4   | 未找到token      
   5   | 密码错误         
   6   | 超出流量限制      
   7   | 超出日期限制
   8   | 连接服务器超时