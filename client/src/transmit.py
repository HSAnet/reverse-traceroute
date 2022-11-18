"""Transmission of traceroute measurements to HSA-Net."""
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
