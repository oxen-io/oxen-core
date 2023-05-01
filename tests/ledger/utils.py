from service_node_network import coins, vprint


def balance(c):
    """Shortcut for coins(c,c), particularly useful when c is complex"""
    return coins(c, c)


class StoreFee:
    def __init__(self):
        self.fee = None

    def __call__(self, _, m):
        self.fee = float(m[1][1])
