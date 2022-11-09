from itertools import product
import graphviz

def create_graph(root):
    def resolve(address):
        import socket
        try:
            return True, socket.gethostbyaddr(address)[0]
        except:
            return False, None

    nodes = list(root.flatten())

    # Perform DNS lookup for IP addresses by concurrently calling
    # the resolve function.
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor() as resolver:
        node_addresses = [ node.address for node in nodes ]
        hostnames = resolver.map(resolve, node_addresses)
        for node, (valid, hostname) in zip(nodes, hostnames):
            if valid:
                node.data.hostname = hostname

    graph = graphviz.Digraph(strict=True)

    for node in nodes:
        label = f"{node.address}\n{node.rtt:.2f}"
        if node.data.hostname:
            label = f"{node.data.hostname}\n" + label
        graph.node(str(id(node)), label=label)
    for node in nodes:
        for next_node in node.successors:
            print(f"{node.address} -> {next_node.address}")
            graph.edge(str(id(node)), str(id(next_node)))

    return graph
