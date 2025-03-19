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

import os
import sys
import subprocess
import yaml
import argparse
from jsonschema import validate

# Load YAML file
def load_yaml(file_path):
    """Load a YAML file."""
    try:
        with open(file_path, "r") as yaml_file:
            return yaml.safe_load(yaml_file)
        print(f"✅ [{yaml_filename}] YAML basic schema validation successful!")
    except FileNotFoundError:
        print(f"❌ Error: The file '{file_path}' was not found.", file=sys.stderr)
    except PermissionError:
        print(f"❌ Error: Permission denied for file '{file_path}'.", file=sys.stderr)
    except UnicodeDecodeError:
        print(f"❌ Error: Cannot decode '{file_path}', check file encoding.", file=sys.stderr)
    except yaml.YAMLError as e:
        print(f"❌ Error: Invalid YAML format in {file_path}\n{e}", file=sys.stderr)
    except IOError as e:
        print(f"❌ Error: I/O error occurred: {e}", file=sys.stderr)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
    sys.exit(1)

def generate_firewall_rules(nodes_data, tunnels_data, clients_data):
    firewall_rules = {}

    nodes_info = {node: {
        "listen_endpoint": config["service"].get("listen_endpoint"),
        "connect_peers": config["service"].get("connect_peers", []),
        "outbound_ips": config.get("outbound_ips", []),
        "domain": config.get("domain"),
        # By default, the "nic_ips" of a node is "any".
        "nic_ips": config.get("nic_ips", "any")
    } for node, config in nodes_data.items()}

    clients_info = {group: ips if ips != "any" else "any" for group, ips in clients_data.items()}

    for node_name, node_config in nodes_info.items():
        listen_port = node_config["listen_endpoint"].split(":")[-1] if node_config["listen_endpoint"] else None
        
        # outbound/to_peers
        if node_config["connect_peers"]:
            firewall_rules.setdefault(node_name, {}).setdefault("outbound/to_peers", {
                "destination_endpoints": [],
                "protocols": ["udp"]
            })
            for peer in node_config["connect_peers"]:
                if peer in nodes_info:
                    peer_listen_port = nodes_info[peer]["listen_endpoint"].split(":")[-1]
                    firewall_rules[node_name]["outbound/to_peers"]["destination_endpoints"].append(
                        f"{nodes_info[peer]['domain']}:{peer_listen_port}"
                    )
        
        # inbound/from_peer
        for peer, peer_config in nodes_info.items():
            if node_name in peer_config["connect_peers"]:
                firewall_rules.setdefault(node_name, {}).setdefault(f"inbound/from_peer/{peer}", {
                    "source_ips": peer_config["outbound_ips"],
                    "destination_endpoints": [f"{ip}:{listen_port}" for ip in node_config["nic_ips"]]
                        if node_config["nic_ips"] != "any" else f"any:{listen_port}",
                    "protocols": ["udp"]
                })
    
    for tunnel_name, tunnel_config in tunnels_data.items():
        clients = tunnel_config.get("clients", "any")
        
        for entrance in tunnel_config.get("entrances", []):
            entrance_node, listen_port = entrance["node"], entrance["listen_endpoint"].split(":")[-1]
            destination_endpoints = [f"{ip}:{listen_port}" for ip
                in nodes_info[entrance_node]["nic_ips"]] if nodes_info[entrance_node]["nic_ips"] != "any" else f"any:{listen_port}"
            
            if clients == "any":
                rule_name = f"inbound/from_clients/{tunnel_name}/any"
                firewall_rules.setdefault(entrance_node, {}).setdefault(rule_name, {
                    "source_ips": "any",
                    "destination_endpoints": destination_endpoints,
                    "protocols": (["tcp", "udp"] if tunnel_config.get("tcp_tunnel_id") and tunnel_config.get("udp_tunnel_id") else
                                  ["tcp"] if tunnel_config.get("tcp_tunnel_id") else ["udp"])
                })
            else:
                for client_group in clients:
                    rule_name = f"inbound/from_clients/{tunnel_name}/{client_group}"
                    firewall_rules.setdefault(entrance_node, {}).setdefault(rule_name, {
                        "source_ips": clients_info.get(client_group, []),
                        # Use deep copy to avoid YAML anchor.
                        "destination_endpoints": destination_endpoints[:],
                        "protocols": (["tcp", "udp"] if tunnel_config.get("tcp_tunnel_id") and tunnel_config.get("udp_tunnel_id") else
                                      ["tcp"] if tunnel_config.get("tcp_tunnel_id") else ["udp"])
                    })
    
    # outbound/to_entrance
    for client_group, client_ips in clients_info.items():
        for tunnel_name, tunnel_config in tunnels_data.items():
            if tunnel_config.get("clients") and client_group in tunnel_config["clients"]:
                rule_name = f"outbound/to_entrances/{tunnel_name}"
                firewall_rules.setdefault(client_group, {}).setdefault(rule_name, {
                    "destination_endpoints": [],
                    "protocols": (["tcp", "udp"] if tunnel_config.get("tcp_tunnel_id") and tunnel_config.get("udp_tunnel_id") else
                                  ["tcp"] if tunnel_config.get("tcp_tunnel_id") else ["udp"])
                })
                for entrance in tunnel_config["entrances"]:
                    firewall_rules[client_group][rule_name]["destination_endpoints"].append(
                        f"{nodes_info[entrance['node']]['domain']}:{entrance['listen_endpoint'].split(':')[-1]}"
                    )
    
    return firewall_rules

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(description="Generate node firewall rules in YAML output format.")
    parser.add_argument("-n", "--nodes_yaml_file", type=str,
        default=os.path.join(current_dir, "example-firewall-rules", "nodes.yaml"),
        help="Path to the nodes YAML file.")
    parser.add_argument("-t", "--tunnels_yaml_file", type=str,
        default=os.path.join(current_dir, "example-firewall-rules", "tunnels.yaml"),
        help="Path to the tunnels YAML file.")
    parser.add_argument("-c", "--clients_yaml_file", type=str,
        default=os.path.join(current_dir, "example-firewall-rules", "clients.yaml"),
        help="Path to the clients YAML file.")
    parser.add_argument("output_dir", type=str, nargs="?",
        default=os.path.join(current_dir, "example-firewall-rules", "output"),
        help="Output directory for generated JSON files.")

    args = parser.parse_args()

    validate_script = os.path.join(current_dir, "validate-yamls.py")
    validate_args = ["--nodes_yaml_file", args.nodes_yaml_file, "--tunnels_yaml_file", args.tunnels_yaml_file]
    result = subprocess.run(["python", validate_script] + validate_args, stdout=sys.stdout, stderr=sys.stderr)
    exit_code = result.returncode
    if exit_code != 0:
        sys.exit(exit_code)

    nodes_data = load_yaml(args.nodes_yaml_file)
    tunnels_data = load_yaml(args.tunnels_yaml_file)
    clients_data = load_yaml(args.clients_yaml_file)

    firewall_rules = generate_firewall_rules(nodes_data, tunnels_data, clients_data)

    for node, rules in firewall_rules.items():
        output_filepath = f"{args.output_dir}/{node}_firewall_inout_rules.yaml" if node in nodes_data else f"{args.output_dir}/{node}_firewall_out_rules.yaml"
        with open(output_filepath, "w") as f:
            yaml.dump(rules, f, default_flow_style=False)
        print(f"✅ Generated: {output_filepath} for node {node}.")
