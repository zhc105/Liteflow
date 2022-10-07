### 编译Docker镜像

命令示例：
```
cd docker
docker build --build-arg BRANCH=v1.0.2 -t liteflow:v1.0.2 .
```

### 启动容器

脚本示例：
```
#!/bin/bash

entrance_rules=$(cat <<- EOM
EOM
)

forward_rules=$(cat <<- EOM
    {
        "tunnel_id": 100,                   // Tunnel ID和服务端entrance_rules对应
        "destination_addr": "127.0.0.1",    // 为此Tunnel指定转发目标地址
        "destination_port": 1501            // 指定转发目标端口
    },
EOM
)

connect_peers=$(cat <<- EOM
    "1.2.3.4:1901",
EOM
)

docker run --network host --name liteflow-main -d --restart=always \
    --env tag="main" \
    --env max_incoming_peers="0" \
    --env connect_peers="$connect_peers" \
    --env node_id="1001" \
    --env password="your-password" \
    --env entrance_rules="$entrance_rules" \
    --env forward_rules="$forward_rules" \
    liteflow:v1.0.2
```