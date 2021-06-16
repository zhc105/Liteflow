# Liteflow
UDP tunnel &amp; TCP/UDP Port forwarding

### 简介

Liteflow实现了一套简易的可靠UDP传输协议(LiteDT)，并基于这个协议开发了TCP/UDP端口转发工具。Liteflow的客户端和服务端都使用相同的二进制程序，区别只在于配置文件的不同。

你可以用这个工具：

1. 加速TCP协议在高延迟高丢包环境的传输速度，或者保障UDP包传输不丢包并且有序。
2. 通过反向连接将内网端口映射至外网服务器，实现内网端口可以穿越NAT被主动访问。


### 编译和使用手册

```
# clone repo后执行下面的命令开始编译
git submodule update --init --recursive
mkdir build && cd build
cmake ..
make

# 检查版本
./liteflow --version

# 部署配置文件

# 运行，默认读取当前目录下的配置文件，文件名为{二进制程序名}.conf。如程序名为liteflow，则配置文件名为liteflow.conf
./liteflow

# 指定配置文件路径运行
./liteflow -c /path/to/config

# 重新加载配置(目前仅支持重新加载entrance_rules和forward_rules)
kill -SIGUSR1 $(liteflow_pid)
```

####示例1： 服务端1.2.3.4开放TCP 1501端口，映射到客户端192.168.1.100:1501

部署方式：
```
+--------+            +-------------+                    +-------------+             +--------+
| Client |  --------> | Liteflow(C) |  --------------->  | Liteflow(S) |  ---------> | Server |
+--------+  TCP:1501  +-------------+      UDP:1901      +-------------+   TCP:1501  +--------+
                       192.168.1.100                         1.2.3.4
```

服务端(1.2.3.4)配置示例
```
{
    "service": {
        "debug_log": 0,
        "max_incoming_peers": 10,               // 允许同时被最多10个节点访问
    },  

    "transport": {
        "node_id": 1002,                        // 指定此节点的Node ID
        "listen_addr": "0.0.0.0",               // 节点监听地址
        "listen_port": 1901                     // 监听端口
    },  

    "forward_rules": [
        {   
            "tunnel_id": 100,                   // Tunnel ID需要和客户端entrance_rules对应
            "destination_addr": "127.0.0.1",    // 为此Tunnel指定转发目标地址
            "destination_port": 1501,           // 指定转发目标端口
            "protocol": "tcp"                   // 转发协议，不填时默认采用TCP，需要和entrance_rules监听协议一致
        },  
    ]   
}
```

客户端(192.168.1.100)配置示例
```
{
    "service": {
        "debug_log": 0,
        "connect_peers": [
            "1.2.3.4:1901"              // 节点启动后主动连接1.2.3.4:1901
        ]
    },

    "transport": {
        "node_id": 1001                 // 指定此节点的Node ID
    },

    "entrance_rules": [
        {
            "listen_addr": "0.0.0.0",   // 为此Tunnel指定监听地址
            "listen_port": 1501,        // 指定监听端口
            "tunnel_id": 100,           // Tunnel ID和服务端forward_rules对应
            "protocol": "tcp"           // 监听协议，不填时默认采用TCP，需要和forward_rules转发协议一致
        },
    ]
}
```

####示例2： 客户端192.168.1.100开放TCP 1501端口，通过反向连接映射到服务端1.2.3.4:1501

部署方式：
```
+--------+            +-------------+                    +-------------+             +--------+
| Client |  --------> | Liteflow(S) |  <---------------  | Liteflow(C) |  ---------> | Server |
+--------+  TCP:1501  +-------------+      UDP:1901      +-------------+   TCP:1501  +--------+
                          1.2.3.4                         192.168.1.100
```

服务端(1.2.3.4)配置示例
```
{
    "service": {
        "debug_log": 0,
        "max_incoming_peers": 10,       // 允许同时被最多10个节点访问
    },  

    "transport": {
        "node_id": 1002,                // 指定此节点的Node ID
        "listen_addr": "0.0.0.0",       // 节点监听地址
        "listen_port": 1901             // 监听端口
    },  

    "entrance_rules": [
        {
            "listen_addr": "0.0.0.0",   // 为此Tunnel指定监听地址
            "listen_port": 1501,        // 指定监听端口
            "tunnel_id": 100,           // Tunnel ID需要和客户端forward_rules对应
            "node_id": 1001             // 限制此入口仅转发至Node 1001
        },
    ]
}
```

客户端(192.168.1.100)配置示例
```
{
    "service": {
        "debug_log": 0,
        "connect_peers": [
            "1.2.3.4:1901"
        ]
    },

    "transport": {
        "node_id": 1001                         // 指定此节点的Node ID
    },

    "forward_rules": [
        {   
            "tunnel_id": 100,                   // Tunnel ID和服务端entrance_rules对应
            "destination_addr": "127.0.0.1",    // 为此Tunnel指定转发目标地址
            "destination_port": 1501            // 指定转发目标端口
        },  
    ]   
}
```

### Cygwin编译Windows版本
Liteflow支持通过Cygwin编译提供Windows可用版本。

Cygwin必须至少安装以下Packages：
* git
* gcc-core
* gcc-g++
* make
* automake
* cmake
* autoconf
* libtool

其它编译步骤与正常流程相同。编译完成后，将`cygwin1.dll`和产生的`liteflow.exe`复制到需要运行Liteflow的Windows机器上，准备好相应的配置文件并直接运行`liteflow.exe`。
