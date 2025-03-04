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