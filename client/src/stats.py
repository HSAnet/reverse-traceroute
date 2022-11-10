import math
import functools


def __certainty_to_reach_vertices(n, k):
    nominator = sum(math.comb(n, i) * i**k * (-1) ** (n - i - 1) for i in range(n))
    return 1 - nominator / (n**k)


def probes_for_vertex(n, alpha):
    """Returns the number of probes required to reach
    the confidence given by alpha to discover each vertex in the set of n vertices
    every iteration in a total number of iterations given by repeat."""
    p_dest = 1 - alpha
    k = n
    while __certainty_to_reach_vertices(n, k) < p_dest:
        k = k + 1
    return k
