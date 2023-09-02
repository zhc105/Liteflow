#!/usr/bin/env bash

# shellcheck disable=SC2154

declare -g gen_confpath

if [[ -z "${tag}" ]]; then
    gen_confpath="./config/liteflow.conf"
else
    gen_confpath="./config/liteflow-${tag}.conf"
fi

escape_string() {
    str="$1"
    ret=""
    readarray -t ARRAY < <(echo -n "$str")
    for ((i=0; i<${#ARRAY[@]}; i++)); do
        if [[ "$i" == "0" ]]; then
            ret="${ARRAY[$i]}"
        else
            ret="$ret\\n${ARRAY[$i]}"
        fi
    done
}

emplace_variable() {
    key="$1"
    value="$2"
    defvalue="$3"

    if [[ -z "$value" ]]; then
        sed -i 's/${'"$key"'}/'"$defvalue"'/g' $gen_confpath
    else
        sed -i 's/${'"$key"'}/'"$value"'/g' $gen_confpath
    fi
}

generate_config() {
    mv ./config/liteflow.conf.template $gen_confpath

    escape_string "$connect_peers"; connect_peers="$ret"
    escape_string "$entrance_rules"; entrance_rules="$ret"
    escape_string "$forward_rules"; forward_rules="$ret"

    emplace_variable "perf_log" "${perf_log}" "0"
    emplace_variable "max_incoming_peers" "${max_incoming_peers}" "10"
    emplace_variable "prefer_ipv6" "${prefer_ipv6}" "0"
    emplace_variable "node_id" "${node_id}" "9999"
    emplace_variable "listen_addr" "${listen_addr}" "0.0.0.0"
    emplace_variable "listen_port" "${listen_port}" "0"
    emplace_variable "transmit_rate_init" "${transmit_rate_init}" "102400"
    emplace_variable "transmit_rate_max" "${transmit_rate_max}" "104857600"
    emplace_variable "transmit_rate_min" "${transmit_rate_min}" "10240"
    emplace_variable "mtu" "${mtu}" "1428"
    emplace_variable "connect_peers" "${connect_peers}" ""
    emplace_variable "password" "${password}" ""
    emplace_variable "entrance_rules" "${entrance_rules}" ""
    emplace_variable "forward_rules" "${forward_rules}" ""
}

if [ -z "$confpath" ]; then
    # Generate config file for liteflow node
    generate_config
else
    # override confpath
    gen_confpath=$confpath
fi

# Launch liteflow node
./bin/liteflow -c $gen_confpath
