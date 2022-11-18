"""
MIT License

Copyright (c) 2020 Sorbonne Université

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


from math import ceil, log


def stopping_point(k: int, eps: float) -> int:
    """
    Return the number `n_k` of probes that guarantees that the probability of not
    detecting `k` outgoing load-balanced edges is lower than `eps`[@veitch2009failure;@jacquet2018collecter].

    Examples:
        >>> stopping_point(1, 0.05)
        0
        >>> stopping_point(2, 0.05)
        6
        >>> stopping_point(3, 0.05)
        11
        >>> stopping_point(11, 0.05)
        57
        >>> stopping_point(101, 0.05)
        765

    Note:
        There is a typo in the D-Miner paper: n(101) = 765, not 757.
    """
    assert (k >= 1) and (0 <= eps <= 1)
    if k == 1:
        return 0
    return ceil(log(eps / k) / log((k - 1) / k))
