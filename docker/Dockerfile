# Stage 1
FROM alpine:3.15 as builder
RUN apk add --no-cache git build-base libev-dev cmake && \
    mkdir -p /source/build
ARG BRANCH=master

WORKDIR /source

RUN echo "Cloning branch ${BRANCH}"
RUN cd /source && \
    git clone --branch ${BRANCH} https://github.com/zhc105/Liteflow.git && \
    cd Liteflow && \
    git submodule update --init --recursive && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_C_FLAGS="-O2 -g" .. && \
    make

# Stage 2
FROM alpine:3.15
RUN apk add --no-cache bash libev psmisc && \
    mkdir -p /app

ENV tag="main" \
    confpath="" \
    perf_log="0" \
    max_incoming_peers="10" \
    connect_peers="" \
    prefer_ipv6="0" \
    node_id="9999" \
    password="password" \
    listen_addr="0.0.0.0" \
    listen_port="1901" \
    transmit_rate_init="102400" \
    transmit_rate_max="104857600" \
    transmit_rate_min="10240" \
    mtu="1428" \
    entrance_rules="" \
    forward_rules=""

RUN mkdir -p /app/bin && \
    mkdir -p /app/config

WORKDIR /app

COPY --from=builder /source/Liteflow/build/src/liteflow /app/bin
COPY liteflow.conf.template /app/config
COPY docker-start.sh /app

RUN chmod +x /app/docker-start.sh

CMD ["./docker-start.sh"]
