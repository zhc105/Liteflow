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

import yaml
import json
import sys
import os
import subprocess
import argparse
from collections import defaultdict

def load_yaml(file_path):
    """Load a YAML file and return its contents as a dictionary."""
    with open(file_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)

def generate_node_configs(node_file, tunnel_file, output_dir):
    """Generate JSON configuration files for nodes based on YAML input."""
    # Load node and tunnel configurations
    nodes_data = load_yaml(node_file)
    tunnels_data = load_yaml(tunnel_file)

    # Create node_name -> node_id mapping
    node_name_to_id = {
        node_name: node_info.get("service", {}).get("node_id")
        for node_name, node_info in nodes_data.items()
    }

    # Iterate over each node
    for node_name, node_config in nodes_data.items():
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
                f"{nodes_data[peer].get('domain', peer)}:{int(nodes_data[peer]['service'].get('listen_endpoint').split(":")[1])}"
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
        for tunnel_name, tunnel in tunnels_data.items():
            has_multiple_entrances = len(tunnel.get("entrance", [])) > 1
            has_multiple_forwards = len(tunnel.get("forward", [])) > 1
            
            for entrance in tunnel.get("entrance", []):
                if node_name_to_id[entrance["node"]] == node_id:
                    for forward in tunnel.get("forward", []):
                        if "tcp_tunnel_id" in tunnel:
                            entrance_rule = {
                                "tunnel_id": tunnel["tcp_tunnel_id"],
                                "listen_addr": entrance["listen_endpoint"].split(":")[0],
                                "listen_port": int(entrance["listen_endpoint"].split(":")[1]),
                                "protocol": "tcp"
                            }
                            if entrance.get("explicit", False):
                                entrance_rule["node_id"] = node_name_to_id[forward["node"]]
                            config["entrance_rules"].append(entrance_rule)
                        if "udp_tunnel_id" in tunnel:
                            entrance_rule = {
                                "tunnel_id": tunnel["udp_tunnel_id"],
                                "listen_addr": entrance["listen_endpoint"].split(":")[0],
                                "listen_port": int(entrance["listen_endpoint"].split(":")[1]),
                                "protocol": "udp"
                            }
                            if entrance.get("explicit", False):
                                entrance_rule["node_id"] = node_name_to_id[forward["node"]]
                            config["entrance_rules"].append(entrance_rule)
                        # If there are multiple forwards, this is a fault-tolerant
                        # entrance. No need to create a separate tunnel for each
                        # forward.
                        if has_multiple_forwards:
                            break
                            
            config["entrance_rules"] = sorted(config["entrance_rules"], key=lambda x: x["tunnel_id"])
            
            for forward in tunnel.get("forward", []):
                if node_name_to_id[forward["node"]] == node_id:
                    for entrance in tunnel.get("entrance", []):
                        if "tcp_tunnel_id" in tunnel:
                            forward_rule = {
                                "tunnel_id": tunnel["tcp_tunnel_id"],
                                "destination_addr": forward["destination_endpoint"].split(":")[0],
                                "destination_port": int(forward["destination_endpoint"].split(":")[1]),
                                "protocol": "tcp"
                            }
                            if forward.get("explicit", False):
                                forward_rule["node_id"] = node_name_to_id[entrance["node"]]
                            config["forward_rules"].append(forward_rule)
                        if "udp_tunnel_id" in tunnel:
                            forward_rule = {
                                "tunnel_id": tunnel["udp_tunnel_id"],
                                "destination_addr": forward["destination_endpoint"].split(":")[0],
                                "destination_port": int(forward["destination_endpoint"].split(":")[1]),
                                "protocol": "udp"
                            }
                            if forward.get("explicit", False):
                                forward_rule["node_id"] = node_name_to_id[entrance["node"]]
                            config["forward_rules"].append(forward_rule)
                        # If there are multiple entrances, this is a fault-tolerant
                        # forward. No need to create a separate tunnel for each
                        # entrance.
                        if has_multiple_entrances:
                            break
            config["forward_rules"] = sorted(config["forward_rules"], key=lambda x: x["tunnel_id"])

        print("----------------------------------------")
        
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
                peer_name for peer_name, peer_config in nodes_data.items()
                if node_name in peer_config.get("service", {}).get("connect_peers", [])
            ]
            print(f"Peers connecting to this node: {peers if peers else 'None'}")
        
        for rule in config["entrance_rules"]:
            print(f"Listen on {rule['listen_addr']}:{rule['listen_port']} for {rule['protocol'].upper()} tunnel ID {rule['tunnel_id']} ")

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(description="Generate node JSON configurations from YAML files.")
    parser.add_argument("-n", "--nodes_yaml_file", type=str,
        default=os.path.join(current_dir, "example_yamls/nodes.yaml"),
        help="Path to the nodes YAML file.")
    parser.add_argument("-t", "--tunnels_yaml_file", type=str,
        default=os.path.join(current_dir, "example_yamls/tunnels.yaml"),
        help="Path to the tunnels YAML file.")
    parser.add_argument("output_dir", type=str, nargs="?",
        default=os.path.join(current_dir, "example_output"),
        help="Output directory for generated JSON files.")
    
    args = parser.parse_args()

    validate_script = os.path.join(current_dir, "validate-yamls.py")
    result = subprocess.run(["python", validate_script], stdout=sys.stdout, stderr=sys.stderr)
    exit_code = result.returncode
    if exit_code != 0:
        sys.exit(exit_code)

    generate_node_configs(args.nodes_yaml_file, args.tunnels_yaml_file, args.output_dir)
