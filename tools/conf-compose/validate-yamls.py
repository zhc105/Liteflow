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
import json
import yaml
import argparse
import jsonschema
from jsonschema import validate
from collections import defaultdict

# Load JSON Schema
def load_json_schema(file_path):
    """Load a JSON schema file."""
    with open(file_path, "r") as schema_file:
        return json.load(schema_file)

# Load YAML file
def load_yaml(file_path):
    """Load a YAML file."""
    try:
        with open(file_path, "r") as yaml_file:
            return yaml.safe_load(yaml_file)
        print(f"✅ [{yaml_filename}] YAML basic schema validation successful!")
    except FileNotFoundError:
        print(f"❌ Error: The file '{file_path}' was not found.")
    except PermissionError:
        print(f"❌ Error: Permission denied for file '{file_path}'.")
    except UnicodeDecodeError:
        print(f"❌ Error: Cannot decode '{file_path}', check file encoding.")
    except IOError as e:
        print(f"❌ Error: I/O error occurred: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

# Validate YAML file against JSON Schema
def validate_basic_schema_of_yaml(yaml_data, schema, yaml_filename):
    """
    Validate YAML content against the given JSON Schema.
    Returns a list of errors, if any.
    """
    try:
        jsonschema.validate(instance=yaml_data, schema=schema)
        print(f"✅ [{yaml_filename}] YAML basic schema validation successful!")
    except jsonschema.exceptions.ValidationError as e:
        print(f"❌ [{yaml_filename}] YAML basic schema validation failed: {e.message}")
        print(f"🔹 Error field: {'.'.join(map(str, e.path))}")
        print(f"🔹 JSON Path: {e.json_path}")
        print(f"🔹 Expected format: {e.schema}")
        return False
    
    return True

# Validate nodes.yaml additional constraints
def validate_nodes_yaml(nodes_data):
    """
    Additional validations for nodes.yaml:
    1. Section names must be unique.
    2. service.node_id values must be unique.
    3. connect_peers must not contain duplicates.
    4. connect_peers must reference existing sections.
    5. Nodes and their peers must have the same transport.password.
    """
    seen_section_names = set()
    seen_node_ids = set()
    transport_passwords = {}

    for section_name, section_data in nodes_data.items():
        # Check section name uniqueness
        if section_name in seen_section_names:
            return f"Duplicate section name found: {section_name}"
        seen_section_names.add(section_name)

        # Check unique node_id
        node_id = section_data.get("service", {}).get("node_id")
        if node_id in seen_node_ids:
            return f"Duplicate node_id found: {node_id}"
        seen_node_ids.add(node_id)

        # Check connect_peers uniqueness and validity
        connect_peers = section_data.get("service", {}).get("connect_peers", [])
        if len(connect_peers) != len(set(connect_peers)):
            return f"Duplicate entries in connect_peers for {section_name}"

        for peer in connect_peers:
            if peer not in nodes_data:
                return f"connect_peers references non-existent node '{peer}' in {section_name}"

        # Check transport.password consistency
        password = section_data.get("transport", {}).get("password")
        if password:
            transport_passwords[section_name] = password

    # Ensure all connected nodes have the same transport.password
    for section_name, section_data in nodes_data.items():
        connect_peers = section_data.get("service", {}).get("connect_peers", [])
        for peer in connect_peers:
            if peer in transport_passwords and section_name in transport_passwords:
                if transport_passwords[peer] != transport_passwords[section_name]:
                    return f"Mismatched transport.password between {section_name} and {peer}"

    return None

# Validate tunnels.yaml additional constraints
def validate_tunnels_yaml(tunnels_data, nodes_data):
    """
    Additional validations for tunnels.yaml:
    1. All tcp_tunnel_id and udp_tunnel_id must be unique across all sections.
    2. Each section's entrance node_id must be unique, and forward node_id must be unique.
    3. Each section's clients.nic_ip values must be unique.
    4. No duplicate listen_endpoint for the same node_id across all sections.
    5. entrance and forward node_id must exist in nodes.yaml.
    6. Each entrance-forward node pair must have a valid connection in nodes.yaml.
    """
    tunnel_ids = set()
    listen_endpoints = defaultdict(set)

    all_node_names = set(nodes_data.keys())

    for section_name, section_data in tunnels_data.items():
        # Validate tunnel ID uniqueness
        tcp_id = section_data.get("tcp_tunnel_id")
        udp_id = section_data.get("udp_tunnel_id")
        if tcp_id in tunnel_ids:
            return f"Duplicate tcp_tunnel_id: {tcp_id}"
        if udp_id in tunnel_ids:
            return f"Duplicate udp_tunnel_id: {udp_id}"
        tunnel_ids.update(filter(None, [tcp_id, udp_id]))

        # Validate entrance and forward uniqueness and existence
        entrance_nodes = set()
        forward_nodes = set()
        
        for entrance in section_data.get("entrance", []):
            node_name = entrance["node"]
            listen_endpoint = entrance["listen_endpoint"]
            if node_name in entrance_nodes:
                return f"Duplicate entrance node {node_name} in {section_name}"
            # Ensure that node exists in nodes.yaml
            if node_name not in all_node_names:
                return f"Node {node_name} in entrance of {section_name} not found in nodes.yaml"
            if listen_endpoint in listen_endpoints[node_name]:
                return f"Duplicate listen_endpoint {listen_endpoint} for node {node_name}"
            listen_endpoints[node_name].add(listen_endpoint)
            entrance_nodes.add(node_name)

        for forward in section_data.get("forward", []):
            node_name = forward["node"]
            if node_name in forward_nodes:
                return f"Duplicate forward node {node_name} in {section_name}"
            # Ensure that node exists in nodes.yaml
            if node_name not in all_node_names:
                return f"Node {node_name} in forward of {section_name} not found in nodes.yaml"
            forward_nodes.add(node_name)

        # Validate entrance-forward connectivity in nodes.yaml
        for entrance_node_name in entrance_nodes:
            for forward_node_name in forward_nodes:
                entrance_peers = nodes_data.get(entrance_node_name, {}).get("service", {}).get("connect_peers", [])
                forward_peers = nodes_data.get(forward_node_name, {}).get("service", {}).get("connect_peers", [])
                if forward_node_name not in entrance_peers and entrance_node_name not in forward_peers:
                    return f"No connectivity between entrance node {entrance_node_name} and forward node {forward_node_name} in {section_name}"

    return None

# Validate clients.yaml additional constraints
def validate_clients_yaml(clients_data):
    """
    Additional validations for clients.yaml:
    1. Section names must be unique.
    2. Each section's values must be unique.
    """
    seen_section_names = set()

    for section_name, ip_list in clients_data.items():
        # Check section name uniqueness
        if section_name in seen_section_names:
            return f"Duplicate section name found: {section_name}"
        seen_section_names.add(section_name)

        # Check if values are unique
        if len(ip_list) != len(set(ip_list)):
            return f"Duplicate values found in {section_name}"

    return None

# Main function to validate all YAML files
# We will try to find as many errors as possible, except for file IO issue.
def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(description="conf-compose YAML format validation tool")

    # Allow both positional and optional named arguments
    parser.add_argument("-n", "--nodes_yaml_file", type=str,
        default=os.path.join(current_dir, "example_yamls/nodes.yaml"),
        help="Path to the nodes YAML file.")
    parser.add_argument("-t", "--tunnels_yaml_file", type=str,
        default=os.path.join(current_dir, "example_yamls/tunnels.yaml"),
        help="Path to the tunnels YAML file.")
    parser.add_argument("-c", "--clients_yaml_file", type=str,
        default=os.path.join(current_dir, "example_yamls/clients.yaml"),
        help="Path to the clients YAML file.")

    args = parser.parse_args()

    # Load JSON Schemas
    nodes_schema = load_json_schema("./schema-nodes.json")
    tunnels_schema = load_json_schema("./schema-tunnels.json")
    if args.clients_yaml_file is not None:
        clients_schema = load_json_schema("./schema-clients.json")
    else:
        clients_schema = None

    # Load YAML files
    nodes_data = load_yaml(args.nodes_yaml_file)
    tunnels_data = load_yaml(args.tunnels_yaml_file)
    if args.clients_yaml_file is not None:
        clients_data = load_yaml(args.clients_yaml_file)

    failed = False

    # Validate nodes.yaml with JSON Schema
    # Ensures:
    # 1. Correct structure (object with valid keys)
    # 2. Each section has "service" and "transport"
    # 3. Valid node_id, listen_endpoint, and password format
    if not validate_basic_schema_of_yaml(nodes_data, nodes_schema, args.nodes_yaml_file):
        failed = True

    # Validate tunnels.yaml with JSON Schema
    # Ensures:
    # 1. Sections follow correct format
    # 2. Valid tcp_tunnel_id, udp_tunnel_id, entrance, forward, and clients
    if not validate_basic_schema_of_yaml(tunnels_data, tunnels_schema, args.tunnels_yaml_file):
        failed = True

    # Validate clients.yaml with JSON Schema
    # Ensures:
    # 1. Each section is an array
    # 2. IPs and CIDR formats are correct
    if args.clients_yaml_file is not None:
        if not validate_basic_schema_of_yaml(clients_data, clients_schema, args.clients_yaml_file):
            failed = True

    # Additional validation
    errmsg = validate_nodes_yaml(nodes_data)
    if errmsg is not None:
        print(f"❌ [{args.nodes_yaml_file}] YAML logic validation failed: {errmsg}")
        failed = True

    errmsg = validate_tunnels_yaml(tunnels_data, nodes_data)
    if errmsg is not None:
        print(f"❌ [{args.tunnels_yaml_file}] YAML logic validation failed: {errmsg}")
        failed = True

    if args.clients_yaml_file is not None:
        errmsg = validate_clients_yaml(clients_data)
        if errmsg is not None:
            print(f"❌ [{args.clients_yaml_file}] YAML logic validation failed: {errmsg}")
            failed = True

    # Finish successfully
    if not failed:
        print("✅ All YAML files validated successfully.")
        exit(0)
    else:
        print(f"❌ Failed to validate one or multiple YAML files. Please check the error message.")
        exit(1)

if __name__ == "__main__":
    main()
