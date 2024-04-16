# Use the official Ubuntu 20.04 image as the base image
FROM ubuntu:22.04

# Install necessary packages to run ipmininet
RUN apt-get update && \
    apt-get install -y python3 python3-pip git sudo iputils-ping

# Upgrade pip to the latest version
RUN python3 -m pip install --upgrade pip

# Install ipmininet using pip
RUN pip install --upgrade git+https://github.com/cnp3/ipmininet.git@v1.1
RUN python3 -m ipmininet.install -q