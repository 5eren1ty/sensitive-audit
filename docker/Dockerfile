FROM rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        findutils \
        hyperfine \
        jq \
        python3 \
        python3-venv \
        rsync \
        sqlite3 \
        strace \
        time \
        tree \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["/bin/bash"]

