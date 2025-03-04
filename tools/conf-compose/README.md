# conf-compose
一个用于更方便地管理和生成集群内多个liteflow实例配置文件的工具。通过YAML定义集群内所有的node实例，和tunnel隧道信息，本工具可以自动化生成各个node的JSON配置文件，避免手工维护多个实例的配置文件，降低人为出错概率。

## 使用说明
首先准备好两个YAML文件，一个文件用来定义当前集群内的所有node实例和信息，另一个文件用来定义所有的tunnel隧道信息。具体的文件格式请参考example_yamls目录下给出的示例。

然后运行
```
./conf-compose.py -n <nodes.yaml file path> -t <nodes.yaml file path> <output_dir>
```

在指定的`<output_dir>`输出目录中，可以找到所有实例的配置文件。

运行完成后，屏幕后将会输出连接到每个实例的其它实例及端口信息，以及实例监听的所有端口，便于配置防火墙规则。

本工具已附带一个example，请运行
```
./conf-compose.py -n example_yamls/nodes.yaml -t example_yamls/tunnels.yaml example_output
```

本工具会检查提供的YAML的格式和内容是否符合要求。

## 容灾设置
在liteflow的设置中，`entrance_rule`可以显式指定tunnel另一端的节点的`node_id`，则此规则仅用于转发到该指定下一级节点。例如：
```json
{
    "tunnel_id": 1011,
    "listen_addr": "0.0.0.0",
    "listen_port": 1010,
    "protocol": "tcp",
    "node_id": 1
}
```

如果`entrance_rule`不指定下一级的`node_id`，如果有多个peer连接上来并提供和该`entrance_rule`相同的`tunnel_id`，则liteflow只会将该tunnel的数据转到到其中某一个peer。如果此peer之后断开了连接，则liteflow会选择转发给下一个peer。这是一种容灾措施，避免单个forward节点的故障导致一个tunnel完全不可用。请注意，这不能用于实现负载均衡。

同样地，`forward_rule`也有类似的行为，避免单个`entrance`节点的故障导致一个tunnel完全不可用。

在conf-compose的设置中，这可以通过在一个规则下设置多个`entrance`或`forward`来实现，请参考example。

同一个规则下，如果只有单个`forward`，则其`entrance`可以设置`explicit`为`true`（默认为`false`），生成的`entrance_rule`中会严格指定`forward`节点的`node_id`。同样地，如果只有单个`entrance`，则其`forward`可以设置`explict`为`true`，生成的`forward_rule`中会严格指定`entrance`节点的`node_id`。

## 生成拓扑图
本工具可以生成Graphviz的dot文件和图形（支持png, svg, pdf, jpg, jpeg, bmp, gif, tiff这些格式）。运行
```
./draw-graphviz.py -n <nodes.yaml file path> -t <nodes.yaml file path> -d <generated .dot file path> -i <generated image file path>
```

例如，提供的example会生这样的图形：
![liteflow.png](./example_output/liteflow.png)
