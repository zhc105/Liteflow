/*
 * Copyright (c) 2021, Moonflow <me@zhc105.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define _CONFIG_C_
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "config.h"
#include "litedt_messages.h"
#include "util.h"
#include "json.h"
#include "sha256.h"

#define MAX_CONF_SIZE           1048576
#define MAX_CONF_NAME_LENGTH    1023

typedef struct parser_entry parser_entry_t;
typedef int (*custom_parser_handler)(json_value *value, parser_entry_t *entry, void *addr);

struct parser_entry {
    const char              *key;
    json_type               type;
    int                     maxlen;
    void                    *addr;
    custom_parser_handler   handler;
    int                     mask;
};

static int normal_parser(json_value *value, parser_entry_t *entry, void *addr);
static int protocol_parser(json_value *value, parser_entry_t *entry, void *addr);
static int peers_parser(json_value *list, parser_entry_t *entry, void *addr);

static parser_entry_t static_service_vars_entries[] =
{
    { .key = "debug_log",           .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "perf_log",            .type = json_integer,   .maxlen = sizeof(uint32_t)},
    { .key = "max_incoming_peers",  .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "connect_peers",       .type = json_array,     .maxlen = MAX_PEER_NUM + 1, .handler = peers_parser },
    { .key = "dns_server",          .type = json_string,    .maxlen = ADDRESS_MAX_LEN },
    { .key = "prefer_ipv6",         .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "udp_timeout",         .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "tcp_nodelay",         .type = json_integer,   .maxlen = sizeof(uint32_t) },
    {}
};

static parser_entry_t static_transport_vars_entries[] =
{
    { .key = "node_id",             .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "password",            .type = json_string,    .maxlen = PASSWORD_LEN,     .mask = 1 },
    { .key = "token_expire",        .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "listen_addr",         .type = json_string,    .maxlen = ADDRESS_MAX_LEN },
    { .key = "listen_port",         .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "offline_timeout",     .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "buffer_size",         .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "transmit_rate_init",  .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "transmit_rate_max",   .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "transmit_rate_min",   .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "fec_decode",          .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "fec_group_size",      .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "max_rtt",             .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "min_rtt",             .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "rto_ratio",           .type = json_double,    .maxlen = sizeof(float) },
    { .key = "mtu",                 .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "ack_size",            .type = json_integer,   .maxlen = sizeof(uint32_t) },
    {}
};

static parser_entry_t dynamic_entrance_rules_entries[] =
{
    { .key = "tunnel_id",           .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "node_id",             .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "listen_addr",         .type = json_string,    .maxlen = ADDRESS_MAX_LEN },
    { .key = "listen_port",         .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "protocol",            .type = json_string,    .maxlen = sizeof(uint16_t), .handler = protocol_parser },
    {}
};

static parser_entry_t dynamic_forward_rules_entries[] =
{
    { .key = "tunnel_id",           .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "node_id",             .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "destination_addr",    .type = json_string,    .maxlen = ADDRESS_MAX_LEN },
    { .key = "destination_port",    .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "protocol",            .type = json_string,    .maxlen = sizeof(uint16_t), .handler = protocol_parser },
    {}
};

global_config_t g_config;
static char conf_name[MAX_CONF_NAME_LENGTH + 1] = { 0 };

static int normal_parser(json_value *value, parser_entry_t *entry, void *addr)
{
    if (entry->type == json_integer) {
        if (entry->maxlen == sizeof(uint8_t)) {
            *(uint8_t*)addr = value->u.integer;
        } else if (entry->maxlen == sizeof(uint16_t)) {
            *(uint16_t*)addr = value->u.integer;
        } else if (entry->maxlen == sizeof(uint32_t)) {
            *(uint32_t*)addr = value->u.integer;
        }
    } else if (entry->type == json_double) {
        if (entry->maxlen == sizeof(float)) {
            *(float*)addr = value->u.dbl;
        } else if (entry->maxlen == sizeof(double)) {
            *(double*)addr = value->u.dbl;
        }
    } else if (entry->type == json_string) {
        if (value->u.string.length >= entry->maxlen) {
            LOG("Configuration entry '%s' length exceed %d.\n",
                entry->key, entry->maxlen);
            return PARSE_FAILED;
        }

        strncpy((char *)addr, value->u.string.ptr, entry->maxlen - 1);
    } else {
        LOG("Unsupported config entry type: %d\n", entry->type);
        return PARSE_FAILED;
    }

    return NO_ERROR;
}

static int protocol_parser(json_value *value, parser_entry_t *entry, void *addr)
{
    char *ptr = value->u.string.ptr;
    if (!strcasecmp(ptr, "tcp")) {
        *(uint16_t*)addr = PROTOCOL_TCP;
    } else if (!strcasecmp(ptr, "udp")) {
        *(uint16_t*)addr = PROTOCOL_UDP;
    } else {
        LOG("Protocol not support: %s\n", ptr);
        return PARSE_FAILED;
    }

    return NO_ERROR;
}

static int peers_parser(json_value *list, parser_entry_t *entry, void *addr)
{
    int array_idx;
    int ret = NO_ERROR;
    char *pos;

    bzero(addr, (MAX_PEER_NUM + 1) * DOMAIN_PORT_MAX_LEN);

    if (list->type != json_array) {
        LOG("rules object is not a json_array.\n");
        return PARSE_FAILED;
    }

    pos = (char *)addr;
    for (array_idx = 0; array_idx < list->u.array.length; ++array_idx) {
        json_value *item = list->u.array.values[array_idx];
        if (array_idx >= MAX_PORT_NUM)
            break;
        if (item->type != json_string)  {
            LOG("Parse peers failed at index: %d, element is not a "
                "json_string.\n", array_idx);
            return PARSE_FAILED;
        }

        if (item->u.string.length >= DOMAIN_PORT_MAX_LEN) {
            LOG("Parse peers failed at index: %d, length limit exceed.\n",
                array_idx);
            return PARSE_FAILED;
        }

        strncpy(pos, item->u.string.ptr, DOMAIN_PORT_MAX_LEN - 1);
        pos += DOMAIN_PORT_MAX_LEN;
    }

    return NO_ERROR;
}

int parse_entries_from_jobject(
        json_value *jobject,
        parser_entry_t *entries,
        void *base
        )
{
    int ret = NO_ERROR;

    if (jobject->type != json_object) {
        LOG("This entry is not a json_object.\n");
        return PARSE_FAILED;
    }

    for (int i = 0; i < jobject->u.object.length; i++) {
        char *name = jobject->u.object.values[i].name;
        json_value *value = jobject->u.object.values[i].value;

        for (parser_entry_t *entry = &entries[0]; entry->key; entry++) {
            if (strcmp(entry->key, name) != 0)
                continue;
            if (value->type != entry->type) {
                LOG("Configuration entry '%s' type mismatch, expect: %d, actual: %d.\n",
                    name, entry->type, value->type);
                return PARSE_FAILED;
            }

            if (entry->handler) {
                // call handler for customer parser
                ret = entry->handler(
                    value,
                    entry,
                    (void *)((uint8_t*)base + (intptr_t)entry->addr));
            } else {
                ret = normal_parser(
                    value,
                    entry,
                    (void *)((uint8_t*)base + (intptr_t)entry->addr));
            }

            if (ret != NO_ERROR)
                return ret;
        }
    }

    return NO_ERROR;
}

int parse_rules_array(
    json_value *list,
    void *rules,
    size_t rule_size,
    parser_entry_t *entries)
{
    int array_idx, object_idx;
    int ret = NO_ERROR;
    uint8_t *pos;

    bzero(rules, rule_size * (MAX_PORT_NUM + 1));

    if (list->type != json_array) {
        LOG("rules object is not a json_array.\n");
        return PARSE_FAILED;
    }

    pos = (uint8_t *)rules;
    for (array_idx = 0; array_idx < list->u.array.length; ++array_idx) {
        json_value *item = list->u.array.values[array_idx];
        if (array_idx >= MAX_PORT_NUM)
            break;
        if (item->type != json_object)  {
            LOG("Parse rules failed at index: %d, element is not a "
                "json_object.\n", array_idx);
            return PARSE_FAILED;
        }

        ret = parse_entries_from_jobject(item, entries, (void *)pos);
        if (ret != NO_ERROR) {
            LOG("Parse allow_list failed at index: %d.\n", array_idx);
            return ret;
        }

        pos += rule_size;
    }

    return NO_ERROR;
}

int parse_rules(
    json_value *obj,
    entrance_rule_t *entrances,
    forward_rule_t *forwards)
{
    int i, ret = NO_ERROR;
    if (obj->type != json_object) {
        LOG("Configuration is not a json_object.\n");
        return PARSE_FAILED;
    }

    for (i = 0; i < obj->u.object.length; i++) {
        char *name = obj->u.object.values[i].name;
        json_value *value = obj->u.object.values[i].value;

        if (!strcmp(name, "entrance_rules")) {
            ret = parse_rules_array(
                value,
                (void *)entrances,
                sizeof(entrance_rule_t),
                dynamic_entrance_rules_entries);
        } else if (!strcmp(name, "forward_rules")) {
            ret = parse_rules_array(
                value,
                (void *)forwards,
                sizeof(forward_rule_t),
                dynamic_forward_rules_entries);
        }

        if (ret != NO_ERROR)
            return ret;
    }

    return NO_ERROR;
}

void debug_print_entries(const char *prefix, parser_entry_t *entries)
{
    for (parser_entry_t *entry = &entries[0]; entry->key; entry++) {
        // ignore entries with customer parser due to the type unpredictable
        if (entry->handler != NULL)
            continue;
        if (entry->mask) {
            DBG("%s/%s: ***\n", prefix, entry->key);
            continue;
        }
        switch (entry->type) {
        case json_integer:
            {
                uint32_t intval = 0;
                if (entry->maxlen == sizeof(uint8_t)) {
                    intval = *(uint8_t*)entry->addr;
                } else if (entry->maxlen == sizeof(uint16_t)) {
                    intval = *(uint16_t*)entry->addr;
                } else if (entry->maxlen == sizeof(uint32_t)) {
                    intval = *(uint32_t*)entry->addr;
                }
                DBG("%s/%s: %u\n", prefix, entry->key, intval);
                break;
            }
        case json_double:
            {
                double doubleval = 0.0;
                if (entry->maxlen == sizeof(float)) {
                    doubleval = *(float*)entry->addr;
                } else if (entry->maxlen == sizeof(double)) {
                    doubleval = *(double*)entry->addr;
                }
                DBG("%s/%s: %f\n", prefix, entry->key, doubleval);
                break;
            }
        case json_string:
            DBG("%s/%s: %s\n", prefix, entry->key, (char*)entry->addr);
            break;
        }
    }
}

void load_config_file(const char *filename)
{
    char *buf;
    char error_buf[512];
    json_value *obj;
    json_settings settings;
    long fsize = 0;
    int nread, i;
    int ret = NO_ERROR;
    FILE *f = fopen(filename, "rb");
    if (NULL == f) {
        LOG("Config file %s open failed!\n", filename);
        exit(FILE_NOT_FOUND);
    }
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize >= MAX_CONF_SIZE) {
        LOG("Config file too large\n");
        exit(PARSE_FAILED);
    }

    strncpy(conf_name, filename, MAX_CONF_NAME_LENGTH - 1);
    buf = (char *)malloc(fsize + 1);
    if (NULL == buf) {
        LOG("Alloc memory failed\n");
        exit(NOT_ENOUGH_RESOURCES);
    }
    nread = fread(buf, fsize, 1, f);
    if (!nread) {
        LOG("Failed to read config file\n");
        exit(FILE_NOT_FOUND);
    }
    buf[fsize] = '\0';
    fclose(f);

    bzero(&settings, sizeof(json_settings));
    settings.settings |= json_enable_comments;
    obj = json_parse_ex(&settings, buf, fsize, error_buf);
    if (NULL == obj) {
        LOG("json_parse: %s\n", error_buf);
        exit(PARSE_FAILED);
    }

    if (obj->type != json_object) {
        LOG("Configuration is not a json_object.\n");
        exit(PARSE_FAILED);
    }

    for (i = 0; i < obj->u.object.length; i++) {
        char *name = obj->u.object.values[i].name;
        json_value *value = obj->u.object.values[i].value;

        if (strcmp(name, "service") == 0) {
            ret = parse_entries_from_jobject(
                value,
                static_service_vars_entries,
                NULL);
            if (ret != NO_ERROR) {
                LOG("Failed to parse service settings: %d.\n", ret);
                assert(0);
            }
        } else if (strcmp(name, "transport") == 0) {
            ret = parse_entries_from_jobject(
                value,
                static_transport_vars_entries,
                NULL);
            if (ret != NO_ERROR) {
                LOG("Failed to parse service settings: %d.\n", ret);
                assert(0);
            }
        }
    }

    ret = parse_rules(obj, g_config.entrance_rules, g_config.forward_rules);
    if (ret != NO_ERROR) {
        LOG("Failed to parse rules: %d.\n", ret);
        assert(0);
    }

    free(buf);
    json_value_free(obj);

    /* Post configuration check */
    if (g_config.transport.fec_group_size > 127)
        g_config.transport.fec_group_size = 127;
    if (g_config.transport.mtu > LITEDT_MTU_MAX) {
        LOG("Warning: MTU should not be greater than %u\n", LITEDT_MTU_MAX);
        g_config.transport.mtu = LITEDT_MTU_MAX;
    }
    if (g_config.transport.mtu <= LITEDT_MAX_HEADER) {
        LOG("Warning: MSS should not be less or equal than %u\n",
            LITEDT_MAX_HEADER);
        g_config.transport.mtu = LITEDT_MAX_HEADER + 1;
    }

    /* Dump configurations to debug log */
    if (g_config.service.debug_log) {
        DBG("Load config success:\n");
        debug_print_entries("service", static_service_vars_entries);
        debug_print_entries("transport", static_transport_vars_entries);
    }

    if (g_config.service.tcp_nodelay) {
        LOG("enable TCP no-delay\n");
    }
}

int reload_config_file()
{
    char *buf = NULL;
    char error_buf[512];
    json_value *obj = NULL;
    json_settings settings;
    int ret = NO_ERROR;
    long fsize = 0;
    int nread;
    unsigned int i;
    static entrance_rule_t temp_entrances[MAX_PORT_NUM + 1];
    static forward_rule_t temp_forwards[MAX_PORT_NUM + 1];
    FILE *f = fopen(conf_name, "rb");
    if (NULL == f) {
        LOG("ReloadConf: Config file %s open failed!\n", conf_name);
        ret = FILE_NOT_FOUND;
        goto errout;
    }
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize >= MAX_CONF_SIZE) {
        LOG("ReloadConf: Config file too large\n");
        ret = PARSE_FAILED;
        goto errout;
    }

    strncpy(conf_name, conf_name, MAX_CONF_NAME_LENGTH - 1);
    buf = (char *)malloc(fsize + 1);
    if (NULL == buf) {
        LOG("ReloadConf: Alloc memory failed\n");
        ret = NOT_ENOUGH_RESOURCES;
        goto errout;
    }
    nread = fread(buf, fsize, 1, f);
    if (!nread) {
        LOG("ReloadConf: Failed to read config file\n");
        ret = FILE_NOT_FOUND;
        goto errout;
    }

    buf[fsize] = '\0';
    fclose(f);

    bzero(&settings, sizeof(json_settings));
    settings.settings |= json_enable_comments;
    obj = json_parse_ex(&settings, buf, fsize, error_buf);
    if (NULL == obj) {
        LOG("ReloadConf: json_parse: %s\n", error_buf);
        ret = PARSE_FAILED;
        goto errout;
    }

    ret = parse_rules(obj, temp_entrances, temp_forwards);
    if (ret != NO_ERROR)
        goto errout;

    memcpy(g_config.entrance_rules, temp_entrances, sizeof(temp_entrances));
    memcpy(g_config.forward_rules, temp_forwards, sizeof(temp_forwards));

errout:
    if (buf != NULL)
        free(buf);
    if (obj != NULL)
        json_value_free(obj);

    return ret;
}

void global_config_init()
{
    for (parser_entry_t *entry = &static_service_vars_entries[0]; entry->key; entry++)
        entry->addr =
            !strcmp(entry->key, "debug_log") ? (void*)&g_config.service.debug_log :
            !strcmp(entry->key, "perf_log") ? (void*)&g_config.service.perf_log :
            !strcmp(entry->key, "node_id") ? (void*)&g_config.service.node_id :
            !strcmp(entry->key, "listen_addr") ? (void*)g_config.service.listen_addr :
            !strcmp(entry->key, "listen_port") ? (void*)&g_config.service.listen_port :
            !strcmp(entry->key, "max_incoming_peers") ? (void*)&g_config.service.max_incoming_peers :
            !strcmp(entry->key, "connect_peers") ? (void*)g_config.service.connect_peers :
            !strcmp(entry->key, "dns_server") ? (void*)g_config.service.dns_server :
            !strcmp(entry->key, "prefer_ipv6") ? (void*)&g_config.service.prefer_ipv6 :
            !strcmp(entry->key, "udp_timeout") ? (void*)&g_config.service.udp_timeout :
            !strcmp(entry->key, "tcp_nodelay") ? (void*)&g_config.service.tcp_nodelay :
            NULL;

    for (parser_entry_t *entry = &static_transport_vars_entries[0]; entry->key; entry++)
        entry->addr =
            !strcmp(entry->key, "password") ? (void*)g_config.transport.password :
            !strcmp(entry->key, "token_expire") ? (void*)&g_config.transport.token_expire :
            !strcmp(entry->key, "offline_timeout") ? (void*)&g_config.transport.offline_timeout :
            !strcmp(entry->key, "buffer_size") ? (void*)&g_config.transport.buffer_size :
            !strcmp(entry->key, "transmit_rate_init") ? (void*)&g_config.transport.transmit_rate_init :
            !strcmp(entry->key, "transmit_rate_max") ? (void*)&g_config.transport.transmit_rate_max :
            !strcmp(entry->key, "transmit_rate_min") ? (void*)&g_config.transport.transmit_rate_min :
            !strcmp(entry->key, "fec_decode") ? (void*)&g_config.transport.fec_decode :
            !strcmp(entry->key, "fec_group_size") ? (void*)&g_config.transport.fec_group_size :
            !strcmp(entry->key, "max_rtt") ? (void*)&g_config.transport.max_rtt :
            !strcmp(entry->key, "min_rtt") ? (void*)&g_config.transport.min_rtt :
            !strcmp(entry->key, "rto_ratio") ? (void*)&g_config.transport.rto_ratio :
            !strcmp(entry->key, "mtu") ? (void*)&g_config.transport.mtu :
            !strcmp(entry->key, "ack_size") ? (void*)&g_config.transport.ack_size :
            NULL;

    for (parser_entry_t *entry = &dynamic_entrance_rules_entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "tunnel_id") == 0) ? (void*)offsetof(entrance_rule_t, tunnel_id) :
            (strcmp(entry->key, "node_id") == 0) ? (void*)offsetof(entrance_rule_t, node_id) :
            (strcmp(entry->key, "listen_addr") == 0) ? (void*)offsetof(entrance_rule_t, listen_addr) :
            (strcmp(entry->key, "listen_port") == 0) ? (void*)offsetof(entrance_rule_t, listen_port) :
            (strcmp(entry->key, "protocol") == 0) ? (void*)offsetof(entrance_rule_t, protocol) :
            NULL;

    for (parser_entry_t *entry = &dynamic_forward_rules_entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "tunnel_id") == 0) ? (void*)offsetof(forward_rule_t, tunnel_id) :
            (strcmp(entry->key, "node_id") == 0) ? (void*)offsetof(forward_rule_t, node_id) :
            (strcmp(entry->key, "destination_addr") == 0) ? (void*)offsetof(forward_rule_t, destination_addr) :
            (strcmp(entry->key, "destination_port") == 0) ? (void*)offsetof(forward_rule_t, destination_port) :
            (strcmp(entry->key, "protocol") == 0) ? (void*)offsetof(forward_rule_t, protocol) :
            NULL;

    /* initialize default config */
    g_config.service.debug_log              = 0;
    g_config.service.perf_log               = 0;
    g_config.service.node_id              = (rand() & 0xFFFF) ? : 1;
    memset(g_config.service.listen_addr, 0, ADDRESS_MAX_LEN);
    g_config.service.listen_port          = 0;
    g_config.service.max_incoming_peers     = 0;
    bzero(g_config.service.dns_server, ADDRESS_MAX_LEN);
    g_config.service.prefer_ipv6            = 0;
    g_config.service.udp_timeout            = 120;
    g_config.service.tcp_nodelay            = 0;

    
    bzero(g_config.transport.password, PASSWORD_LEN);
    g_config.transport.token_expire         = 120;
    g_config.transport.offline_timeout      = 120;
    g_config.transport.buffer_size          = 10 * 1024 * 1024;
    g_config.transport.transmit_rate_init   = 100 * 1024;           // 100KB/s
    g_config.transport.transmit_rate_max    = 100 * 1024 * 1024;    // 100MB/s
    g_config.transport.transmit_rate_min    = 10 * 1024;            // 10KB/s
    g_config.transport.fec_decode           = 0;
    g_config.transport.fec_group_size       = 0;
    g_config.transport.max_rtt              = 1000 * USEC_PER_MSEC;
    g_config.transport.min_rtt              = 50 * USEC_PER_MSEC;
    g_config.transport.rto_ratio            = 1.5;
    g_config.transport.mtu                  = LITEDT_MTU_MAX;
    g_config.transport.ack_size             = 100;

    bzero(g_config.entrance_rules, sizeof(g_config.entrance_rules));
    bzero(g_config.forward_rules, sizeof(g_config.forward_rules));
}
