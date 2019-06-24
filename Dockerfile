# Build Geth in a stock Go builder container
FROM golang:1.12-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers g++ bash cmake

ADD . /PlatON-Go
RUN cd /PlatON-Go && make all

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates libstdc++ bash tzdata
COPY --from=builder /PlatON-Go/build/bin/platon /usr/local/bin/
COPY --from=builder /PlatON-Go/build/bin/ethkey /usr/local/bin/
COPY --from=builder /PlatON-Go/entrypoint.sh /usr/local/bin/
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

ENV ENABLE_DEBUG=false
ENV ENABLE_PPROF=false
ENV ENABLE_WS=false
ENV WSAPI=
ENV ENABLE_RPC=false
ENV RPCAPI=
ENV BOOTNODES=
ENV NEW_ACCOUNT=false
ENV INIT=false
ENV VERBOSITY=3
ENV ENBALE_DISCOVER=false
ENV ENABLE_V5DISC=false
ENV ENABLE_CBFT_TRACING=false
ENV P2PPORT=16789
ENV WSPORT=6080
ENV RPCPORT=6789
ENV PPROFPORT=6060
ENV MAXPEERS=25
ENV MAXCONSENSUSPEERS=75
ENV ENABLE_LIGHT_SRV=false
ENV SYNCMODE=full

VOLUME /data/platon
EXPOSE 6060 6080 6789 16789 16789/udp
CMD ["entrypoint.sh"]
