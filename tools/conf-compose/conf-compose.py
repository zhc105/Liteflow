# Copyright (c) 2025, Xnerv Wang <xnervwang@gmail.com>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

#!/usr/bin/env python3

"""
This script generates JSON configuration files for nodes based on YAML input.
It processes two YAML files:
  1. One defining node configurations
  2. One defining tunnel configurations

Each node gets a corresponding JSON file with its service, transport, and tunnel rules.

Command-line arguments:
  - `-n, --nodes FILE` : Path to the nodes YAML file (default: 'nodes.yaml')
  - `-t, --tunnels FILE` : Path to the tunnels YAML file (default: 'tunnels.yaml')
  - `output_dir` : Output directory for generated JSON files (default: 'output_configs')
"""

# TODO list:
#   1. Basic verification, check required fields in each yaml file.
#   2. For each connect_peer specified in nodes.yaml, check if it really exists.
#   3. For each entrance rule specified in tunnels.yaml, we should verify if the peer
#       relation exists in nodes.yaml.
#   4. Should verify if forward_node_id exists.
#   5. If a node has no listen_endpoint, it must have at least one peer.

import yaml
import json
import os
import argparse
from collections import defaultdict

def load_yaml(file_path):
    """Load a YAML file and return its contents as a dictionary."""
    with open(file_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)

def is_valid_port(port):
    """Check if a port number is valid (1-65535)."""
    return isinstance(port, int) and 1 <= port <= 65535

def validate_nodes(node_data):
    """Validate the nodes.yaml data."""
    node_ids = set()
    for node_name, node in node_data.items():
        service = node.get("service", {})
        transport = node.get("transport", {})
        
        node_id = service.get("node_id")
        if node_id in node_ids:
            raise ValueError(f"Duplicate node_id detected: {node_id}")
        node_ids.add(node_id)
        
        if "listen_endpoint" in service:
            listen_addr, listen_port = service["listen_endpoint"].split(":")
            listen_port = int(listen_port)
            if not is_valid_port(listen_port):
                raise ValueError(f"Invalid listen port for node {node_name}: {listen_port}")
            if service.get("max_incoming_peers", 0) <= 0:
                raise ValueError(f"Node {node_name} has listen_endpoint but max_incoming_peers <= 0")
            if "domain" not in node:
                raise ValueError(f"Node {node_name} has listen_endpoint but no domain specified")
        
        # Validate that every node has a password set
        if "password" not in transport:
            raise ValueError(f"Node {node_name} must have a password set in the transport section")
        
        # Validate password consistency with peers
        password = transport["password"]
        for peer in service.get("connect_peers", []):
            if peer in node_data:
                peer_password = node_data[peer].get("transport", {}).get("password")
                if peer_password and peer_password != password:
                    raise ValueError(f"Node {node_name} and peer {peer} have mismatched passwords")

def validate_tunnels(tunnel_data):
    """Validate the tunnels.yaml data."""
    listen_endpoints = defaultdict(set)
    
    for tunnel_name, tunnel in tunnel_data.items():
        if "tcp_tunnel_id" not in tunnel and "udp_tunnel_id" not in tunnel:
            raise ValueError(f"Tunnel {tunnel_name} must specify at least one of tcp_tunnel_id or udp_tunnel_id")
        
        forward_node_id = tunnel["forward_node_id"]
        for entrance in tunnel.get("entrance", []):
            if entrance["node_id"] == forward_node_id:
                raise ValueError(f"Tunnel {tunnel_name}: forward_node_id {forward_node_id} cannot match entrance node_id {entrance['node_id']}")
            
            listen_endpoint = entrance["listen_endpoint"]
            node_id = entrance["node_id"]
            if listen_endpoint in listen_endpoints[node_id]:
                raise ValueError(f"Duplicate listen_endpoint {listen_endpoint} for node {node_id} in tunnel configurations")
            listen_endpoints[node_id].add(listen_endpoint)
        
        destination_port = int(tunnel["destination_endpoint"].split(":")[1])
        if not is_valid_port(destination_port):
            raise ValueError(f"Invalid destination port {destination_port} in tunnel {tunnel_name}")

def load_yaml(file_path):
    """Load a YAML file and return its contents as a dictionary."""
    with open(file_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)

def generate_node_configs(node_file, tunnel_file, output_dir):
    """Generate JSON configuration files for nodes based on YAML input."""
    # Load node and tunnel configurations
    node_data = load_yaml(node_file)
    tunnel_data = load_yaml(tunnel_file)

    # Validate inputs
    validate_nodes(node_data)
    validate_tunnels(tunnel_data)
    
    # Iterate over each node
    for node_name, node_config in node_data.items():
        print("----------------------------------------")
        
        node_id = node_config['service']['node_id']
        node_domain = node_config.get("domain", "")
        
        # Split listen_endpoint into address and port
        service_config = node_config.get("service", {}).copy()
        if "listen_endpoint" in service_config:
            listen_addr, listen_port = service_config["listen_endpoint"].split(":")
            service_config["listen_addr"] = listen_addr
            service_config["listen_port"] = int(listen_port)
            del service_config["listen_endpoint"]
        
        # Convert connect_peers node names to domain:port format
        if "connect_peers" in service_config:
            service_config["connect_peers"] = [
                f"{node_data[peer].get('domain', peer)}:{int(node_data[peer]['service'].get('listen_endpoint').split(":")[1])}"
                for peer in service_config["connect_peers"]
            ]
            if not service_config["connect_peers"]:
                del service_config["connect_peers"]
        
        # Construct JSON structure
        config = {
            "service": service_config,
            "transport": node_config.get("transport", {}),
            "entrance_rules": [],
            "forward_rules": []
        }
        
        # Process entrance rules (acting as tunnel entry points)
        for tunnel_name, tunnel in tunnel_data.items():
            for entrance in tunnel.get("entrance", []):
                if entrance["node_id"] == node_id:
                    if "tcp_tunnel_id" in tunnel:
                        config["entrance_rules"].append({
                            "tunnel_id": tunnel["tcp_tunnel_id"],
                            "listen_addr": entrance["listen_endpoint"].split(":")[0],
                            "listen_port": int(entrance["listen_endpoint"].split(":")[1]),
                            "protocol": "tcp",
                            "node_id": tunnel["forward_node_id"] if entrance.get("explicit", True) else None
                        })
                    if "udp_tunnel_id" in tunnel:
                        config["entrance_rules"].append({
                            "tunnel_id": tunnel["udp_tunnel_id"],
                            "listen_addr": entrance["listen_endpoint"].split(":")[0],
                            "listen_port": int(entrance["listen_endpoint"].split(":")[1]),
                            "protocol": "udp",
                            "node_id": tunnel["forward_node_id"] if entrance.get("explicit", True) else None
                        })
        config["entrance_rules"] = sorted(config["entrance_rules"], key=lambda x: x["tunnel_id"])

        # Process forward rules (acting as tunnel endpoints)
        for tunnel_name, tunnel in tunnel_data.items():
            if tunnel["forward_node_id"] == node_id:
                if "tcp_tunnel_id" in tunnel:
                    config["forward_rules"].append({
                        "tunnel_id": tunnel["tcp_tunnel_id"],
                        "destination_addr": tunnel["destination_endpoint"].split(":")[0],
                        "destination_port": int(tunnel["destination_endpoint"].split(":")[1]),
                        "protocol": "tcp"
                    })
                if "udp_tunnel_id" in tunnel:
                    config["forward_rules"].append({
                        "tunnel_id": tunnel["udp_tunnel_id"],
                        "destination_addr": tunnel["destination_endpoint"].split(":")[0],
                        "destination_port": int(tunnel["destination_endpoint"].split(":")[1]),
                        "protocol": "udp"
                    })
        config["forward_rules"] = sorted(config["forward_rules"], key=lambda x: x["tunnel_id"])
        
        # Create JSON configuration file
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{node_name}.conf")
        with open(output_path, "w", encoding="utf-8") as json_file:
            json.dump(config, json_file, indent=4)
        print(f"Generated {output_path}")
        
        # Print firewall rule information for terminal output
        print(f"\n[Node {node_id}: {node_name}{' (domain: ' + node_domain + ')' if node_domain else ''}]")
        if "listen_addr" in service_config:
            print(f"Service Listen UDP Endpoint for Peers: {service_config['listen_addr']}:{service_config['listen_port']}")
            peers = [
                peer_name for peer_name, peer_config in node_data.items()
                if node_name in peer_config.get("service", {}).get("connect_peers", [])
            ]
            print(f"Peers connecting to this node: {peers if peers else 'None'}")
        
        for rule in config["entrance_rules"]:
            print(f"Listen on {rule['listen_addr']}:{rule['listen_port']} for {rule['protocol'].upper()} tunnel ID {rule['tunnel_id']} ")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate node JSON configurations from YAML files.")
    parser.add_argument("-n", "--nodes", type=str, default="nodes.yaml", help="Path to the nodes YAML file.")
    parser.add_argument("-t", "--tunnels", type=str, default="tunnels.yaml", help="Path to the tunnels YAML file.")
    parser.add_argument("output_dir", type=str, nargs="?", default="output_configs", help="Output directory for generated JSON files.")
    
    args = parser.parse_args()
    generate_node_configs(args.nodes, args.tunnels, args.output_dir)
