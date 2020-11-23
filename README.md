# Liteflow
UDP tunnel &amp; TCP/UDP Port forwarding

### 简介

Liteflow实现了一套简易的可靠UDP传输协议(LiteDT)，并基于这个协议开发了TCP/UDP端口转发工具。Liteflow的客户端和服务端都使用相同的二进制程序，区别只在于配置文件的不同。

你可以用这个工具：

1. 加速TCP协议在高延迟高丢包环境的传输速度，或者保障UDP包传输不丢包并且有序。
2. 通过反向连接将内网端口映射至外网服务器，实现内网端口可以穿越NAT被主动访问。


### 编译和使用手册

```
# 编译
git submodule init
git submodule update --recursive
cmake .
make

目前只支持在源码目录编译，不支持使用另一个目录存放编译生成文件，例如`mkdir out && cd out && cmake .. && make`。

# 检查版本
./liteflow --version

# 部署配置文件，与程序在同一目录下，文件名为{二进制程序名}.conf。如程序名为liteflow，则配置文件名为liteflow.conf

# 运行
./liteflow

# 重新加载配置(仅支持listen_list和allow_list)
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

服务端配置
```
{
    "debug_log": 0,
    "flow_local_addr": "0.0.0.0",
    "flow_local_port": 1901,
    "send_bytes_per_sec": 5242880,
    "max_rtt": 1000,
    "min_rtt": 100,
    "timeout_rtt_ratio": 1.5,
    "allow_list": 
        [   
            {   
                "map_id": 100,
                "target_addr": "127.0.0.1",
                "target_port": 1501
            }
        ]
}

```

客户端配置
```
{
    "debug_log": 0,
    "map_bind_addr": "192.168.1.100",
    "flow_remote_addr": "1.2.3.4",
    "flow_remote_port": 1901,
    "send_bytes_per_sec": 524288,
    "max_rtt": 1000,
    "min_rtt": 100,
    "timeout_rtt_ratio": 1.5,
    "listen_list": 
        [
            {
                "local_port": 1501,
                "map_id": 100
            }
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

服务端配置
```
{
    "debug_log": 0,
    "map_bind_addr": "0.0.0.0",
    "flow_local_addr": "0.0.0.0",
    "flow_local_port": 1901,
    "send_bytes_per_sec": 5242880,
    "max_rtt": 1000,
    "min_rtt": 100,
    "timeout_rtt_ratio": 1.5,
    "listen_list": 
        [
            {
                "local_port": 1501,
                "map_id": 100
            }
        ]
}

```

客户端配置
```
{
    "debug_log": 0,
    "flow_remote_addr": "1.2.3.4",
    "flow_remote_port": 1901,
    "send_bytes_per_sec": 524288,
    "max_rtt": 1000,
    "min_rtt": 100,
    "timeout_rtt_ratio": 1.5,
    "allow_list": 
        [   
            {   
                "map_id": 100,
                "target_addr": "127.0.0.1",
                "target_port": 1501
            }
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