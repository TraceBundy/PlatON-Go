#!/usr/bin/env bash

set -e
set -v

PLATON=/usr/local/bin/platon
PLATON_HOME=/data/platon

if [ "${NEW_ACCOUNT}" = "true" ]; then
	echo "123456" >/tmp/password
	${PLATON} --datadir ${PLATON_HOME}/data account new --password /tmp/password
	rm /tmp/password
fi

if [ "${INIT}" = "true" ]; then
	${PLATON} --datadir ${PLATON_HOME}/data init ${PLATON_HOME}/genesis.json
fi

DEBUG=
if [ "${ENABLE_DEBUG}" = "true" ]; then
	DEBUG=--debug
fi

PPROF=
if [ "${ENABLE_PPROF}" = "true" ]; then
	PPROF="--pprof --pprofaddr 0.0.0.0 --pprofport ${PPROFPORT}"
fi

WS=
if [ "${ENABLE_WS}" = "true" ]; then
	WS="--ws --wsaddr 0.0.0.0 --wsorigins '*' --wsport ${WSPORT} --wsapi ${WSAPI}"
fi

RPC=
if [ "${ENABLE_RPC}" = "true" ]; then
	RPC="--rpc --rpcaddr 0.0.0.0 --rpcport ${RPCPORT} --rpcapi ${RPCAPI}"
fi

BOOT=
if [ "${BOOTNODES}" != "" ]; then
	BOOT="--bootnodes ${BOOTNODES}"
fi

DISCOVER=--nodiscover
if [ "${ENABLE_DISCOVER}" = "true" ]; then
	DISCOVER=
fi

V5DISC=
if [ "${ENABLE_V5DISC}" = "true" ]; then
	V5DISC=--v5disc
fi

TRACING=
if [ "${ENABLE_CBFT_TRACING}" = "true" ];then
    TRACING="--cbft.breakpoint tracing"
fi

${PLATON} --identity platon --datadir ${PLATON_HOME}/data \
	--nodekey ${PLATON_HOME}/data/nodekey \
	--port ${P2PPORT} ${DEBUG} --verbosity ${VERBOSITY} \
	${PPROF} ${WS} ${RPC} \
	--metrics --ipcdisable --txpool.nolocals \
	--gcmode archive ${BOOT} ${DISCOVER} ${V5DISC} ${TRACING}
