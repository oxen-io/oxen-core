#!/usr/bin/python3

# This script generates the quorum interconnection matrices for different quorum sizes stored in
# src/quorumnet/conn_matrix.h and used to establish a quorum p2p mesh that establishes a set of
# connections with good partial connectivity using a minimal number of outgoing connections.
#
# It works by looking at the number of different paths of 2 hops or less (1 hop meaning a direct
# connection, 2 meaning a connection that passes through 1 intermediate node) and looks for
# connections between least-connected nodes that increases the most two-hop minimum paths.  It then
# establishes this "best" connection, then restarts, continuing until it has achieved a minimum
# 2-hop connectivity from every node to every other node.
#
# This isn't any guarantee that this procedure generates the absolute best connectivity mesh, but it
# appears to do fairly well.


# If you want to see every path that gets added and the before/after two-hop-connectivity graph
# after each addition, set this to true:
TRACE = False
TRACE = True

# N sizes to calculate for.  The default calculates for all possible quorums that are capable of
# achieving supermajority for blink and obligations quorums (10, 7 required) and checkpoint quorums
# (20, 13 required)
N = range(7, 21)

# This defines how much 2-path connectivity we require for different values of N
def min_connections(n):
    return 4 if n <= 10 else 2

# Some stuff you might need:   apt install python3-numpy python3-terminaltables
import numpy as np
from terminaltables import SingleTable

nodes = None
conns = None

def count_paths_within_two(i, j):
    if i > j:
        i, j = j, i
    paths = 0
    neighbours = []
    for r in range(0, j):
        if conns[r, j] or conns[j, r] > 0:
            neighbours.append(r)
    for c in range(j+1, nodes):
        if conns[j, c] or conns[c, j] > 0:
            neighbours.append(c)
    for n in neighbours:
        if n == i or conns[n, i] > 0 or conns[i, n] > 0:
            paths += 1
    return paths


def within_two_matrix():
    z = np.zeros([nodes, nodes], dtype=int)
    for i in range(nodes):
        for j in range(nodes):
            if i == j:
                continue
            z[i, j] = count_paths_within_two(i, j)
    return z


def print_conns():
    table_data = [["i", "Connections (1 = out, x = in)", "≤2 paths", "Connectivity:"], ["\n".join(str(x) for x in range(nodes)), "", "", ""]]
    for r in range(nodes):
        if table_data[1][1]:
            table_data[1][1] += "\n"
        table_data[1][1] += "".join('-' if r == c else 'x' if conns[c,r] else str(conns[r,c]) for c in range(nodes))

    z = within_two_matrix()
    for r in range(nodes):
        if table_data[1][2]:
            table_data[1][2] += "\n"
        table_data[1][2] += "".join('-' if r == c else str(z[r,c]) for c in range(nodes))

    for i in range(nodes):
        myouts, myins = 0, 0
        for j in range(nodes):
            if conns[i, j]:
                myouts += 1
            elif conns[j, i]:
                myins += 1
        if table_data[1][3]:
            table_data[1][3] += "\n"
        table_data[1][3] += "{} (= {} out + {} in)".format(myouts + myins, myouts, myins)

    print(SingleTable(table_data).table)


def min_within_two():
    m = None
    for i in range(nodes):
        for j in range(i+1, nodes):
            c = count_paths_within_two(i, j)
            if m is None or c < m:
                m = c
    return m


def count_not_within_two(min_paths):
    c = 0
    for i in range(nodes):
        for j in range(i+1, nodes):
            if count_paths_within_two(i, j) <= min_paths:
                c += 1
    return c


def highlight(s, hl, code="\033[32m"):
    return "{}{}\033[0m".format(code, s) if hl else "{}".format(s)


cpp = ""


for n in N:
    nodes = n
    conns = np.zeros([nodes, nodes], dtype=int)

    target = min_connections(nodes)

    min_paths = 0
    last_min_paths = 0
    while min_paths < target:
        best = (nodes + nodes, count_not_within_two(min_paths))
        best_ij = (0, 0)
        for i in range(nodes):
            outgoing_conns = sum(conns[i,j] for j in range(nodes)) + 1
            for j in range(nodes):
                incoming_conns = sum(conns[k,j] for k in range(nodes)) + 1
                if i == j or conns[i, j] or conns[j, i]:
                    continue
                conns[i, j] = 1
                c = (outgoing_conns + incoming_conns, count_not_within_two(min_paths))
                if c < best:
                    best_ij = (i, j)
                    best = c
                    best_conns = outgoing_conns
                conns[i, j] = 0
        if TRACE:
            before = within_two_matrix()
        conns[best_ij[0], best_ij[1]] = 1
        if TRACE:
            print("Chose connection [{},{}]".format(*best_ij))
            after = within_two_matrix()
            for r in range(nodes):
                print("".join(
                    highlight('-' if r == c else '#' if conns[c,r] and conns[r,c] else 'x' if conns[c,r] else conns[r,c], (r,c)==best_ij) for c in range(nodes)
                    ), end='')
                print(" : " if r == nodes // 2 else "   ", end='')
                print("".join(highlight('-' if r == c else before[r,c], after[r,c] > before[r,c], "\033[33m") for c in range(nodes)), end='')
                print(" => " if r == nodes // 2 else "    ", end='')
                print("".join(highlight('-' if r == c else after[r,c], after[r,c] > before[r,c]) for c in range(nodes)))


        min_paths = min_within_two()

        if min_paths > last_min_paths:
            print("\n\n\n\n====================================================\nConstructed {}-min-two-hop-paths (N={})\n====================================================\n".format(
                min_paths, nodes))
            print_conns()
            last_min_paths = min_paths
            print("\n\n\n\n")

    cpp += "template<> constexpr std::array<bool, {N}*{N}> quorum_conn_matrix<{N}>{{{{\n".format(N=n);
    for r in range(nodes):
        cpp += "    " + ",".join(str(conns[r,c]) for c in range(nodes)) + ",\n"
    cpp += "}};\n\n"

print("C++ code for quorumnet/conn_matrix.h:\n\n\n")
print(cpp)
