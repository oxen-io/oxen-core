from expected import *


def test_init(net, mike, hal, ledger):
    """
    Tests that the node fakenet got initialized properly, and that the wallet starts up and shows
    the right address.
    """

    # All nodes should be at the same height:
    heights = [x.rpc("/get_height").json()["height"] for x in net.all_nodes]
    height = max(heights)
    assert heights == [height] * len(net.all_nodes)

    assert mike.height(refresh=True) == height
    assert mike.balances() > (0, 0)
    assert hal.height(refresh=True) == height
    assert hal.balances() == (0, 0)

    address = hal.address()

    def check_addr(_, m):
        assert address.startswith(m[1][1]) and address.endswith(m[1][2])

    check_interactions(
        ledger,
        MatchScreen([r"^OXEN wallet$", r"^(\w+)\.\.(\w+)$"], check_addr),
        Do.both,  # Hitting both on the main screen shows us the full address details
        ExactScreen(["Regular address", "(fakenet)"]),
        Do.right,
        MatchMulti("Address", address),
        Do.right,
        ExactScreen(["Back"]),
        Do.both,
        MatchScreen([r"^OXEN wallet$", r"^(\w+)\.\.(\w+)$"], check_addr),
    )
