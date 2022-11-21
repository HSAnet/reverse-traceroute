"""
Copyright 2022 University of Applied Sciences Augsburg

This file is part of Augsburg-Traceroute.

Augsburg-Traceroute is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Augsburg-Traceroute is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Augsburg-Traceroute.
If not, see <https://www.gnu.org/licenses/>.
"""

import requests


def transmit_measurement(measurement: dict):
    """Transmit the measurement to the HSA-Net server."""
    response = requests.post(
        "http://playground.net.hs-augsburg.de:9999/post_trace",
        headers={"Content-type": "application/json"},
        json=measurement,
        auth=requests.auth.HTTPBasicAuth(
            "augsburg-traceroute",
            "26XiTwgXQYsiwdrgGVWw",
        ),
    )
    response.raise_for_status()
