"""
Network topology rendering module.

This module provides functionality to visualize network topology from scan results
using NetworkX and Matplotlib.
"""
import json
import networkx as nx
import matplotlib.pyplot as plt


def load_scan_results(filename):
    """
    Load scan results from a JSON file.

    Args:
        filename (str): Path to the JSON file containing scan results

    Returns:
        dict: Parsed JSON data containing scan results
    """
    with open(filename, 'r') as file:
        data = json.load(file)
    return data


def create_network_topology(data):
    """
    Create a network topology graph from scan results.

    Args:
        data (list): List of dictionaries containing host information

    Returns:
        networkx.Graph: Graph representing the network topology
    """
    G = nx.Graph()

    # Extract the router information (first entry in the list)
    router = data[0]
    router_ip = router['ip']
    router_hostname = router['services'][router_ip]['hostname']
    router_label = f"{router_hostname}\n{router_ip}"

    # Add the router node
    G.add_node(router_ip, label=router_label, color='red')

    # Add the rest of the devices and connections
    for device in data[1:]:
        device_ip = device['ip']
        device_hostname = device['services'][device_ip]['hostname']
        device_label = f"{device_hostname}\n{device_ip}"

        # Add device node
        G.add_node(device_ip, label=device_label, color='blue')

        # Add an edge between the router and the device
        G.add_edge(router_ip, device_ip)

    return G


def draw_network_topology(G):
    """
    Draw and display the network topology graph.

    Args:
        G (networkx.Graph): Network topology graph to visualize
    """
    pos = nx.spring_layout(G)
    labels = nx.get_node_attributes(G, 'label')
    colors = [G.nodes[node]['color'] for node in G.nodes]

    nx.draw(
        G, pos, labels=labels, node_color=colors,
        with_labels=True, node_size=3000, font_size=10, font_color='white'
    )
    plt.show()


def main():
    """
    Main function to load scan results and visualize network topology.
    """
    # Load the scan results from the JSON file
    scan_results = load_scan_results('scan_results.json')

    # Create the network topology
    G = create_network_topology(scan_results)

    # Draw the network topology
    draw_network_topology(G)
