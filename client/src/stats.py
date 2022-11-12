from math import log, ceil

def probes_for_vertex(k, alpha):
    """Returns the number of probes required to reach
    the confidence given by alpha to discover each vertex in the set of n vertices
    every iteration in a total number of iterations given by repeat."""

    return ceil(log(alpha / k) / log((k-1)/k))
