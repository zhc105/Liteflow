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

import argparse
import yaml
import os
import random
from graphviz import Digraph

# Supported image formats for Graphviz
SUPPORTED_IMAGE_FORMATS = {"png", "svg", "pdf", "jpg", "jpeg", "bmp", "gif", "tiff"}

# Generate a random color in hex format
def random_color():
    """Generate a random hex color code."""
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

def load_yaml(filename):
    """Load a YAML file and return its parsed content."""
    with open(filename, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)

def parse_nodes(node_data):
    """
    Parse node configurations from the YAML data.
    
    Returns a dictionary where:
    - Key: node_id (integer)
    - Value: a dictionary containing:
      - node name
      - listen_endpoint (if available)
      - list of connected peers
    """
    nodes = {}
    for node_name, config in node_data.items():
        node_id = config["service"]["node_id"]
        listen_endpoint = config["service"].get("listen_endpoint", None)
        nodes[node_id] = {
            "name": node_name,
            "listen_endpoint": listen_endpoint,
            "connect_peers": config["service"].get("connect_peers", []),
        }
    return nodes

def parse_tunnels(tunnel_data):
    """
    Parse tunnel configurations from the YAML data.
    
    Returns a dictionary where:
    - Key: tunnel group name (e.g., "server.to_node1_and_node2.fault-tolerant.tunnels")
    - Value: a list of tunnel entries within that group
    """
    tunnels = {}
    for tunnel_name, config in tunnel_data.items():
        tunnel_group = tunnels.setdefault(tunnel_name, [])

        # 分别提取 TCP 和 UDP 隧道 ID（如果存在）
        tunnel_ids = {}
        if "tcp_tunnel_id" in config:
            tunnel_ids["tcp_tunnel_id"] = config["tcp_tunnel_id"]
        if "udp_tunnel_id" in config:
            tunnel_ids["udp_tunnel_id"] = config["udp_tunnel_id"]

        entrances = config.get("entrance", [])
        forwards = config.get("forward", [])

        tunnel_group.append({
            "tunnel_id": tunnel_ids,  # 存储为字典，包含 TCP 和 UDP ID
            "entrance": entrances,
            "forward": forwards,
        })
    return tunnels

def extract_filename_and_extension(filepath, default_name="liteflow.png"):
    """
    Extract filename and extension from the given filepath.
    Validate if the extension is supported.
    """
    filename, extension = os.path.splitext(filepath)
    extension = extension.lstrip(".").lower()

    # Use default name if not specified
    if not filename:
        filename, extension = os.path.splitext(default_name)
        extension = extension.lstrip(".")

    # Validate extension
    if extension not in SUPPORTED_IMAGE_FORMATS:
        raise ValueError(f"Unsupported image format: {extension}. Supported formats: {', '.join(SUPPORTED_IMAGE_FORMATS)}")

    return filename, extension

def generate_dot(nodes, tunnels, dot_filename="liteflow.dot", image_filename="liteflow.png"):
    """
    Generate a Graphviz DOT file and an image visualization.
    
    - Nodes are represented as circles with node_id and listen_endpoint.
    - Solid arrows indicate peer connections.
    - Dashed arrows indicate tunnel connections with listen and destination endpoints.
    - Each tunnel group has a unique color.
    """
    dot = Digraph("Network")

    # Add nodes
    for node_id, data in nodes.items():
        label = f"{node_id}"
        if data["listen_endpoint"]:
            label += f"\n{data['listen_endpoint']}"
        dot.node(str(node_id), label, shape="circle", style="filled", fillcolor="lightblue")

    # Add peer connections (solid arrows)
    for node_id, data in nodes.items():
        for peer in data["connect_peers"]:
            peer_id = next((nid for nid, ndata in nodes.items() if ndata["name"] == peer), None)
            if peer_id:
                dot.edge(str(node_id), str(peer_id), color="black", penwidth="2.0")

    # Assign a unique color for each tunnel group
    tunnel_colors = {group_name: random_color() for group_name in tunnels.keys()}

    # Add tunnels (dashed arrows with extra information)
    for group_name, tunnel_list in tunnels.items():
        color = tunnel_colors[group_name]  # Use consistent color for the tunnel group

        for tunnel in tunnel_list:
            tunnel_id = tunnel["tunnel_id"]
            for entrance in tunnel["entrance"]:
                entrance_id = str(entrance["node_id"])
                entrance_endpoint = entrance.get("listen_endpoint", "Unknown")

                for forward in tunnel["forward"]:
                    forward_id = str(forward["node_id"])
                    destination_endpoint = forward.get("destination_endpoint", "Unknown")

                    label = f"{tunnel_id}: {entrance_endpoint} → {destination_endpoint}"
                    dot.edge(
                        entrance_id,
                        forward_id,
                        style="dashed",
                        color=color,
                        fontcolor=color,
                        label=label
                    )

    dot.save(dot_filename)

    # Extract filename and extension for rendering
    img_filename, img_extension = extract_filename_and_extension(image_filename)

    # Only apply DPI settings for raster formats (not SVG)
    if img_extension != "svg":
        dot.attr(dpi="300")  # High DPI for better PNG/JPG quality

    # Render image
    dot.render(img_filename, format=img_extension, cleanup=True)

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Generate Graphviz .dot file and image from YAML files.")
    parser.add_argument("-n", "--nodes", type=str, default="nodes.yaml", help="Path to the nodes YAML file.")
    parser.add_argument("-t", "--tunnels", type=str, default="tunnels.yaml", help="Path to the tunnels YAML file.")
    parser.add_argument("-d", "--dot", type=str, default="liteflow.dot", help="Output DOT file name.")
    parser.add_argument("-i", "--image", type=str, default="liteflow.svg", help="Output image file name.")
    
    args = parser.parse_args()

    # Load YAML files
    nodes_yaml = load_yaml(args.nodes)
    tunnels_yaml = load_yaml(args.tunnels)

    # Parse configurations
    nodes = parse_nodes(nodes_yaml)
    tunnels = parse_tunnels(tunnels_yaml)

    # Generate and save network diagram
    generate_dot(nodes, tunnels, args.dot, args.image)

    print(f"Generated dot file {args.dot} and image {args.image} successfully.")
