# GTS
GTS(Geewan Transimit System) provides an new way to transmit you data securely and fast.
## 安装
linux：  

    # install libsodium
    wget https://github.com/jedisct1/libsodium/releases/download/1.0.10/libsodium-1.0.10.tar.gz
    tar xf libsodium-1.0.10.tar.gz && cd libsodium-1.0.10
    ./configure && make -j2 && make install
    echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
    ldconfig

    # git source code and compile
    git clone https://username@github.com/geewan-rd/GTS.git
    cd GTS/ && git checkout develop
    mkdir build && cmake .. && make
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
    "header key":"1234ABCE",                    # 用来解密头部信息的key
    "token":["ff593b9abeb1","ff593b9abeb2"],    # 用来区分客户端的 6 byte HEX 信息，
                                                  使用命令 xxd -l 8 -p /dev/random 生成
    "password":["geewantest1","geewantest2"],   # 按顺序token对应的密码
    "intf":"GTSs_tun",                          # 生成虚拟借口的名称
    "mtu":1432,                                 # 虚拟接口的 MTU
    "net":"10.1.0.1/24",                        # 虚拟借口的ip和子网掩码
    "encrypt":1,                                # 是否对payload部分进行加密（openwrt版本消耗性能较大）
    "shell_up":"/etc/GTS/server_up.sh",         # 启动脚本路径
    "shell_down":"/etc/GTS/server_down.sh",     # 结束脚本路径
    "logfile":"/var/log/GTS-server.log"         # 日志文件路径
    }

client.json:  
配置大致和server端相同

    {
    "server":"0.0.0.0",                         # 服务端ip
    "port":6666,
    "header key":"1234ABCE",
    "token":"b88d9ad8eabb",                     # 客户端使用的token
    "password":"geewantest",                    # token对应的密码
    "intf":"GTSc_tun",
    "mtu":1432,
    "net":"10.1.0.2/24",
    "encrypt":1,
    "beat time":5,                              # 向服务器发送心跳的间隔（秒）
    "shell_up":"/etc/GTS/client_up.sh",
    "shell_down":"/etc/GTS/client_down.sh",
    "logfile":"/var/log/GTS-client.log"
    }

## 运行
服务端：  

    sudo GTS-server -c /etc/GTS/server.json -k header_key(可选)
客户端：  

    sudo GTS-server -c /etc/GTS/server.json -k header_key(可选)

## IPC接口
客户端和服务端都提供了 unix domain socket 形式的IPC接口  
支持的信息格式为json

### 服务端  
#### 添加用户  
发送格式：

    {
        "act":"add_user",               # 添加用户
        "token":"b88d9ad8eabb",         # 添加用户的token
        "password":"789632145",         # 添加用户的pasword
        "txquota":"1024",               # 允许用户消耗的流量（KB）(-1为无限制)
        "expire":"2016/01/02 12:12:00"  # 允许用户在该日期前使用
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
            "token":	"ff593b9abeb1",
            "txquota":	-1,             # 用户剩余可用流量
            "tx":	0,                  # 用户消耗的流量
            "rx":	0                   # 用户消耗的流量
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

 Code   | stat            
 ------ |----------------
 2      | 状态良好         
 3      | header key 错误  
 4      | 未找到token      
 5      | 密码错误         
 6      | 超出流量限制      
 7      | 超出日期限制
