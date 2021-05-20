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
#include "util.h"
#include "json.h"

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
};

int normal_parser(json_value *value, parser_entry_t *entry, void *addr);
int protocol_parser(json_value *value, parser_entry_t *entry, void *addr);

static parser_entry_t static_vars_entries[] =
{
    { .key = "debug_log",           .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "map_bind_addr",       .type = json_string,    .maxlen = ADDRESS_MAX_LEN },
    { .key = "flow_local_addr",     .type = json_string,    .maxlen = ADDRESS_MAX_LEN },
    { .key = "flow_local_port",     .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "flow_remote_addr",    .type = json_string,    .maxlen = ADDRESS_MAX_LEN },
    { .key = "flow_remote_port",    .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "dns_server_addr",     .type = json_string,    .maxlen = ADDRESS_MAX_LEN },
    { .key = "keepalive_timeout",   .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "buffer_size",         .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "send_bytes_per_sec",  .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "fec_group_size",      .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "udp_timeout",         .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "max_rtt",             .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "min_rtt",             .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "timeout_rtt_ratio",   .type = json_double,    .maxlen = sizeof(float) },
    { .key = "ack_size",            .type = json_integer,   .maxlen = sizeof(uint32_t) },
    { .key = "tcp_nodelay",         .type = json_integer,   .maxlen = sizeof(uint32_t) },
    {}
};

static parser_entry_t dynamic_allow_list_entries[] =
{
    { .key = "map_id",      .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "target_addr", .type = json_string,    .maxlen = ADDRESS_MAX_LEN },
    { .key = "target_port", .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "protocol",    .type = json_string,    .maxlen = sizeof(uint16_t), .handler = protocol_parser },
    {}
};

static parser_entry_t dynamic_listen_list_entries[] =
{
    { .key = "local_port",  .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "map_id",      .type = json_integer,   .maxlen = sizeof(uint16_t) },
    { .key = "protocol",    .type = json_string,    .maxlen = sizeof(uint16_t), .handler = protocol_parser },
    {}
};

global_config_t g_config;
static char conf_name[MAX_CONF_NAME_LENGTH + 1] = { 0 };

int normal_parser(json_value *value, parser_entry_t *entry, void *addr)
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
            
        strncpy(addr, value->u.string.ptr, entry->maxlen);
    } else {
        LOG("Unsupported config entry type: %d\n", entry->type);
        return PARSE_FAILED;
    }

    return NO_ERROR;
}

int protocol_parser(json_value *value, parser_entry_t *entry, void *addr)
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

int parse_static_entries_from_jobject(
        json_value *jobject, 
        parser_entry_t *entries
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
                ret = entry->handler(value, entry, entry->addr);
            } else {
                ret = normal_parser(value, entry, entry->addr);
            }

            if (ret != NO_ERROR) 
                return ret;
        }
    }

    return NO_ERROR;
}

int parse_dynamic_entries_from_jobject(
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
                ret = entry->handler(value, entry, (void *)((uint8_t*)base + (intptr_t)entry->addr));
            } else {
                ret = normal_parser(value, entry, (void *)((uint8_t*)base + (intptr_t)entry->addr));
            }

            if (ret != NO_ERROR) 
                return ret;
        }
    }

    return NO_ERROR;
}

int parse_allow_list(json_value *list, allow_access_t *allow_list)
{
    int array_idx, object_idx, ret;
    if (list->type != json_array) {
        LOG("allow_list is not a json array.\n");
        return PARSE_FAILED;
    }
        
    for (array_idx = 0; array_idx < list->u.array.length; ++array_idx) {
        json_value *item = list->u.array.values[array_idx];
        if (array_idx >= MAX_PORT_NUM)
            break;
        if (item->type != json_object)  {
            LOG("Parse allow_list failed at index: %d, element is not a json_object.\n", array_idx);
            return PARSE_FAILED;
        }   

        ret = parse_dynamic_entries_from_jobject(
                item, 
                dynamic_allow_list_entries,
                &allow_list[array_idx]
                );
        if (ret != NO_ERROR) {
            LOG("Parse allow_list failed at index: %d.\n", array_idx);
            return ret;
        }   
    }
}

int parse_listen_list(json_value *list, listen_port_t *listen_list)
{
    int array_idx, object_idx, ret;
    if (list->type != json_array) {
        LOG("listen_list is not a json array.\n");
        return PARSE_FAILED;
    }

    for (array_idx = 0; array_idx < list->u.array.length; ++array_idx) {
        json_value *item = list->u.array.values[array_idx];
        if (array_idx >= MAX_PORT_NUM)
            break;
        if (item->type != json_object)  {
            LOG("Parse listen_list failed at index: %d, element is not a json_object.\n", array_idx);
            return PARSE_FAILED;
        }   

        ret = parse_dynamic_entries_from_jobject(
                item, 
                dynamic_listen_list_entries,
                &listen_list[array_idx]
                );
        if (ret != NO_ERROR) {
            LOG("Parse listen_list failed at index: %d.\n", array_idx);
            return ret;
        }   
    }
}

int parse_dynamic_config(json_value *obj, allow_access_t *allow_list, listen_port_t *listen_list)
{
    int i;
    if (obj->type != json_object) {
        LOG("Configuration is not a json_object.\n");
        return PARSE_FAILED;
    }

    for (i = 0; i < obj->u.object.length; i++) {
        char *name = obj->u.object.values[i].name;
        json_value *value = obj->u.object.values[i].value;

        if (strcmp(name, "allow_list") == 0) {
            parse_allow_list(value, allow_list);
        } else if (strcmp(name, "listen_list") == 0) {
            parse_listen_list(value, listen_list);
        }
    }

    return NO_ERROR;
}

void load_config_file(const char *filename)
{
    char *buf;
    char error_buf[512];
    json_value *obj;
    json_settings settings;
    long fsize = 0;
    int nread, ret;
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

    ret = parse_static_entries_from_jobject(obj, static_vars_entries);
    if (ret != NO_ERROR) {
        LOG("Failed to parse static configurations: %d.\n", ret);
        assert(0);
    }

    ret = parse_dynamic_config(obj, g_config.allow_list, g_config.listen_list);
    if (ret != NO_ERROR) {
        LOG("Failed to parse dynamic configurations: %d.\n", ret);
        assert(0);
    }

    free(buf);
    json_value_free(obj);

    /* Post configuration check */
    if (g_config.fec_group_size > 128) // 128 = automatic adjustment
        g_config.fec_group_size = 127;

    /* Dump configurations to debug log */
    DBG("Load config ok:\n");
    for (parser_entry_t *entry = &static_vars_entries[0]; entry->key; entry++) {
        if (entry->handler != NULL)
            continue; // ignore entries with customer parser due to the type unpredictable
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
                DBG("%-24s: %u\n", entry->key, intval);
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
                DBG("%-24s: %f\n", entry->key, doubleval);
                break;
            }
        case json_string:
            DBG("%-24s: %s\n", entry->key, (char*)entry->addr);
            break;
        } 
    }

    if (g_config.tcp_nodelay) {
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
    static allow_access_t temp_allow_list[MAX_PORT_NUM + 1];
    static listen_port_t temp_listen_list[MAX_PORT_NUM + 1];
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

    bzero(&temp_allow_list, sizeof(temp_allow_list));
    bzero(&temp_listen_list, sizeof(temp_listen_list));
    ret = parse_dynamic_config(obj, temp_allow_list, temp_listen_list);

    if (ret == NO_ERROR) {
        memcpy(g_config.listen_list, temp_listen_list, sizeof(g_config.listen_list));
        memcpy(g_config.allow_list, temp_allow_list, sizeof(g_config.allow_list));
    }

errout:
    if (buf != NULL)
        free(buf);
    if (obj != NULL)
        json_value_free(obj);

    return ret;
}

void global_config_init()
{
    for (parser_entry_t *entry = &static_vars_entries[0]; entry->key; entry++)
        entry->addr = 
            (strcmp(entry->key, "debug_log") == 0) ? (void*)&g_config.debug_log :
            (strcmp(entry->key, "map_bind_addr") == 0) ? (void*)g_config.map_bind_addr :
            (strcmp(entry->key, "flow_local_addr") == 0) ? (void*)g_config.flow_local_addr :
            (strcmp(entry->key, "flow_local_port") == 0) ? (void*)&g_config.flow_local_port :
            (strcmp(entry->key, "flow_remote_addr") == 0) ? (void*)g_config.flow_remote_addr :
            (strcmp(entry->key, "flow_remote_port") == 0) ? (void*)&g_config.flow_remote_port :
            (strcmp(entry->key, "dns_server_addr") == 0) ? (void*)g_config.dns_server_addr :
            (strcmp(entry->key, "keepalive_timeout") == 0) ? (void*)&g_config.keepalive_timeout :
            (strcmp(entry->key, "buffer_size") == 0) ? (void*)&g_config.buffer_size :
            (strcmp(entry->key, "send_bytes_per_sec") == 0) ? (void*)&g_config.send_bytes_per_sec :
            (strcmp(entry->key, "fec_group_size") == 0) ? (void*)&g_config.fec_group_size :
            (strcmp(entry->key, "udp_timeout") == 0) ? (void*)&g_config.udp_timeout :
            (strcmp(entry->key, "max_rtt") == 0) ? (void*)&g_config.max_rtt :
            (strcmp(entry->key, "min_rtt") == 0) ? (void*)&g_config.min_rtt :
            (strcmp(entry->key, "timeout_rtt_ratio") == 0) ? (void*)&g_config.timeout_rtt_ratio :
            (strcmp(entry->key, "ack_size") == 0) ? (void*)&g_config.ack_size :
            (strcmp(entry->key, "tcp_nodelay") == 0) ? (void*)&g_config.tcp_nodelay :
            NULL;

    for (parser_entry_t *entry = &dynamic_allow_list_entries[0]; entry->key; entry++)
        entry->addr = 
            (strcmp(entry->key, "map_id") == 0) ? (void*)offsetof(allow_access_t, map_id) :
            (strcmp(entry->key, "target_addr") == 0) ? (void*)offsetof(allow_access_t, target_addr) :
            (strcmp(entry->key, "target_port") == 0) ? (void*)offsetof(allow_access_t, target_port) :
            (strcmp(entry->key, "protocol") == 0) ? (void*)offsetof(allow_access_t, protocol) :
            NULL;

    for (parser_entry_t *entry = &dynamic_listen_list_entries[0]; entry->key; entry++)
        entry->addr = 
            (strcmp(entry->key, "local_port") == 0) ? (void*)offsetof(listen_port_t, local_port) :
            (strcmp(entry->key, "map_id") == 0) ? (void*)offsetof(listen_port_t, map_id) :
            (strcmp(entry->key, "protocol") == 0) ? (void*)offsetof(listen_port_t, protocol) :
            NULL;
    
    g_config.debug_log = 1;
    strncpy(g_config.map_bind_addr, "0.0.0.0", ADDRESS_MAX_LEN);
    strncpy(g_config.flow_local_addr, "0.0.0.0", ADDRESS_MAX_LEN);
    g_config.flow_local_port    = 0;
    bzero(g_config.flow_remote_addr, DOMAIN_MAX_LEN);
    g_config.flow_remote_port   = 19210;
    bzero(g_config.dns_server_addr, ADDRESS_MAX_LEN);
    g_config.keepalive_timeout  = 300;
    g_config.buffer_size        = 10 * 1024 * 1024;
    g_config.send_bytes_per_sec = 200 * 1024;
    g_config.fec_group_size     = 128;
    g_config.udp_timeout        = 60;
    g_config.max_rtt            = 1000 * MSEC_PER_SEC;
    g_config.min_rtt            = 100 * MSEC_PER_SEC;
    g_config.timeout_rtt_ratio  = 1.5;
    g_config.ack_size           = 100;
    g_config.tcp_nodelay        = 0;
    bzero(g_config.allow_list, sizeof(g_config.allow_list));
    bzero(g_config.listen_list, sizeof(g_config.listen_list));
}
