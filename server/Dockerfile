FROM ubuntu:22.04

WORKDIR /home/build

RUN apt update -y && apt upgrade -y
RUN apt install -y \
    pkg-config \
    gcc-multilib \
    linux-headers-generic \
    libelf-dev \
    clang-14 \
    make

VOLUME [ "${WORKDIR}/bin" ]

COPY libbpf libbpf
COPY bpftool bpftool
COPY src src
