### 编译Docker镜像

命令示例：
默认从作者仓库master分支构建
```
docker build --build-arg BRANCH=master -t liteflow:master .
```

指定构建仓库和分支
```
docker build --build-arg SOURCE=https://github.com/zhc105/Liteflow.git BRANCH=master -t liteflow:master .
```

复制本地代码并构建
```
# option 1
docker build --build-arg SOURCE=local -t liteflow:local .
# option 2
docker build --build-arg SOURCE=. -t liteflow:local .
# option 3
docker build --build-arg SOURCE=./ -t liteflow:local .
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
    liteflow:master
```