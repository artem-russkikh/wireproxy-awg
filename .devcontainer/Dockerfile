FROM golang:1.26-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends make wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash vscode \
    && chown -R vscode:vscode /go

USER vscode
