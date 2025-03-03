# Stage 1
FROM alpine:3.15 as builder
RUN apk add --no-cache git build-base libev-dev cmake && \
    mkdir -p /source/build
ARG SOURCE=https://github.com/zhc105/Liteflow.git
ARG BRANCH=master

WORKDIR /source
# COPY cannot access external directory beyond the build context.
# ARG cannot be used in COPY or other build phase commands.
COPY . /tmp/Liteflow/

RUN case "${SOURCE}" in \
        https://*|http://*|git@*) \
            echo "Cloning repository ${SOURCE}, branch ${BRANCH}"; \
            git clone --branch ${BRANCH} --recursive ${SOURCE} /source/Liteflow ;; \
        local|.|./) \
            echo "Copying local source folder"; \
            mv /tmp/Liteflow /source/Liteflow ;; \
        *) \
            echo "Specify a valid Git URL or \"local\" or \".\"or \"./\" for SOURCE argument."; \
            exit 1 ;; \
    esac

WORKDIR /source/Liteflow
RUN ls -l /source/Liteflow && git submodule update --init --recursive && \
    mkdir -p build && \
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
    fec_decode="0" \
    fec_group_size="0" \
    mtu="1428" \
    entrance_rules="" \
    forward_rules=""

RUN mkdir -p /app/bin && \
    mkdir -p /app/config

WORKDIR /app

COPY --from=builder /source/Liteflow/build/src/liteflow /app/bin
COPY docker/liteflow.conf.template /app/config
COPY docker/docker-start.sh /app

RUN chmod +x /app/docker-start.sh

CMD ["./docker-start.sh"]
