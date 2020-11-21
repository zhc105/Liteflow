/*
 * Copyright (c) 2016, Moonflow <me@zhc105.net>
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
#include <stdio.h>
#include <assert.h>
#include "config.h"
#include "util.h"
#include "json.h"

#define MAX_CONF_SIZE           1048576
#define MAX_CONF_NAME_LENGTH    1023

#define CHECK_OBJECT_TYPE(type, expect) \
    do { \
        if (type != expect) { \
            LOG("ReloadConf: json_object type %u mismatch, expect: %u\n", \
                type, expect); \
            ret = -2; \
            goto errout; \
        } \
    } while(0)

global_config_t g_config;
static char conf_name[MAX_CONF_NAME_LENGTH + 1] = { 0 };

void load_config_file(const char *filename)
{
    char *buf;
    char error_buf[512];
    json_value *obj;
    json_settings settings;
    long fsize = 0;
    int nread;
    unsigned int i;
    FILE *f = fopen(filename, "rb");
    if (NULL == f) {
        LOG("Config file %s open failed!\n", filename);
        exit(-1);
    }
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize >= MAX_CONF_SIZE) {
        LOG("Config file too large\n");
        exit(-2);
    }

    strncpy(conf_name, filename, MAX_CONF_NAME_LENGTH - 1);
    buf = (char *)malloc(fsize + 1);
    if (NULL == buf) {
        LOG("Alloc memory failed\n");
        exit(-2);
    }
    nread = fread(buf, fsize, 1, f);
    if (!nread) {
        LOG("Failed to read config file\n");
        exit(-2);
    }
    buf[fsize] = '\0';
    fclose(f);

    bzero(&settings, sizeof(json_settings));
    obj = json_parse_ex(&settings, buf, fsize, error_buf);
    if (NULL == obj) {
        LOG("json_parse: %s\n", error_buf);
        exit(-3);
    }

    assert(obj->type == json_object);
    for (i = 0; i < obj->u.object.length; i++) {
        char *name = obj->u.object.values[i].name;
        json_value *value = obj->u.object.values[i].value;
        if (!strcmp(name, "debug_log")) {
            assert(value->type == json_integer);
            g_config.debug_log = value->u.integer;
        } else if (!strcmp(name, "map_bind_addr")) {
            char *ptr = value->u.string.ptr;
            assert(value->type == json_string);
            assert(value->u.string.length < ADDRESS_MAX_LEN);
            strncpy(g_config.map_bind_addr, ptr, ADDRESS_MAX_LEN);
        } else if (!strcmp(name, "flow_local_addr")) {
            char *ptr = value->u.string.ptr;
            assert(value->type == json_string);
            assert(value->u.string.length < ADDRESS_MAX_LEN);
            strncpy(g_config.flow_local_addr, ptr, ADDRESS_MAX_LEN);
        } else if (!strcmp(name, "flow_local_port")) {
            assert(value->type == json_integer);
            g_config.flow_local_port = value->u.integer;
        } else if (!strcmp(name, "flow_remote_addr")) {
            char *ptr = value->u.string.ptr;
            assert(value->type == json_string);
            assert(value->u.string.length < DOMAIN_MAX_LEN);
            strncpy(g_config.flow_remote_addr, ptr, DOMAIN_MAX_LEN);
        } else if (!strcmp(name, "flow_remote_port")) {
            assert(value->type == json_integer);
            g_config.flow_remote_port = value->u.integer;
        } else if (!strcmp(name, "dns_server_addr")) {
            char *ptr = value->u.string.ptr;
            assert(value->type == json_string);
            assert(value->u.string.length < ADDRESS_MAX_LEN);
            strncpy(g_config.dns_server_addr, ptr, ADDRESS_MAX_LEN);
        } else if (!strcmp(name, "keepalive_timeout")) {
            assert(value->type == json_integer);
            g_config.keepalive_timeout = value->u.integer;
        }  else if (!strcmp(name, "buffer_size")) {
            assert(value->type == json_integer);
            g_config.buffer_size = value->u.integer;
        } else if (!strcmp(name, "send_bytes_per_sec")) {
            assert(value->type == json_integer);
            g_config.send_bytes_per_sec = value->u.integer;
        } else if (!strcmp(name, "fec_group_size")) {
            assert(value->type == json_integer);
            g_config.fec_group_size = value->u.integer;
            if (g_config.fec_group_size > 127)
                g_config.fec_group_size = 127;
        } else if (!strcmp(name, "udp_timeout")) {
            assert(value->type == json_integer);
            g_config.udp_timeout = value->u.integer;
        } else if (!strcmp(name, "max_rtt")) {
            assert(value->type == json_integer);
            g_config.max_rtt = value->u.integer;
        } else if (!strcmp(name, "min_rtt")) {
            assert(value->type == json_integer);
            g_config.min_rtt = value->u.integer;
        } else if (!strcmp(name, "timeout_rtt_ratio")) {
            assert(value->type == json_double);
            g_config.timeout_rtt_ratio = value->u.dbl;
        } else if (!strcmp(name, "ack_size")) {
            assert(value->type == json_integer);
            g_config.ack_size = value->u.integer;
        } else if (!strcmp(name, "tcp_nodelay")) {
            assert(value->type == json_integer);
            g_config.tcp_nodelay = value->u.integer;
        } else if (!strcmp(name, "allow_list")) {
            unsigned int j, k;
            assert(value->type == json_array);
            for (j = 0; j < value->u.array.length; j++) {
                json_value *v = value->u.array.values[j];
                if (j >= MAX_PORT_NUM)
                    break;
                assert(v->type == json_object);
                for (k = 0; k < v->u.object.length; k++) {
                    char *sub_name = v->u.object.values[k].name;
                    json_value *sub_value = v->u.object.values[k].value;
                    if (!strcmp(sub_name, "map_id")) {
                        assert(sub_value->type == json_integer);
                        g_config.allow_list[j].map_id = sub_value->u.integer;
                    } else if (!strcmp(sub_name, "target_addr")) {
                        char *ptr = sub_value->u.string.ptr;
                        assert(sub_value->type == json_string);
                        assert(sub_value->u.string.length < ADDRESS_MAX_LEN);
                        strncpy(g_config.allow_list[j].target_addr, ptr,
                                ADDRESS_MAX_LEN);
                    } else if (!strcmp(sub_name, "target_port")) {
                        assert(sub_value->type == json_integer);
                        g_config.allow_list[j].target_port
                            = sub_value->u.integer;
                    } else if (!strcmp(sub_name, "protocol")) {
                        assert(sub_value->type == json_string);
                        char *ptr = sub_value->u.string.ptr;
                        if (!strcasecmp(ptr, "tcp")) {
                            g_config.allow_list[j].protocol = PROTOCOL_TCP;
                        } else if (!strcasecmp(ptr, "udp")) {
                            g_config.allow_list[j].protocol = PROTOCOL_UDP;
                        } else {
                            LOG("protocol not support: %s\n", ptr);
                            assert(0);
                        }
                    }
                }
            }
        } else if (!strcmp(name, "listen_list")) {
            unsigned int j, k;
            assert(value->type == json_array);
            for (j = 0; j < value->u.array.length; j++) {
                json_value *v = value->u.array.values[j];
                if (j >= MAX_PORT_NUM)
                    break;
                assert(v->type == json_object);
                for (k = 0; k < v->u.object.length; k++) {
                    char *sub_name = v->u.object.values[k].name;
                    json_value *sub_value = v->u.object.values[k].value;
                    if (!strcmp(sub_name, "local_port")) {
                        assert(sub_value->type == json_integer);
                        g_config.listen_list[j].local_port
                            = sub_value->u.integer;
                    } else if (!strcmp(sub_name, "map_id")) {
                        assert(sub_value->type == json_integer);
                        g_config.listen_list[j].map_id = sub_value->u.integer;
                    } else if (!strcmp(sub_name, "protocol")) {
                        assert(sub_value->type == json_string);
                        char *ptr = sub_value->u.string.ptr;
                        if (!strcasecmp(ptr, "tcp")) {
                            g_config.listen_list[j].protocol = PROTOCOL_TCP;
                        } else if (!strcasecmp(ptr, "udp")) {
                            g_config.listen_list[j].protocol = PROTOCOL_UDP;
                        } else {
                            LOG("protocol not support: %s\n", ptr);
                            assert(0);
                        }
                    }
                }
            }
        }
    }

    free(buf);
    json_value_free(obj);

    DBG("Load config ok:\n");
    DBG("map_bind_addr:      %s\n", g_config.map_bind_addr);
    DBG("flow_local_addr:    %s\n", g_config.flow_local_addr);
    DBG("flow_local_port:    %u\n", g_config.flow_local_port);
    DBG("flow_remote_addr:   %s\n", g_config.flow_remote_addr);
    DBG("flow_remote_port:   %u\n", g_config.flow_remote_port);
    DBG("dns_server_addr:    %s\n", g_config.dns_server_addr);
    DBG("keepalive_timeout:  %u\n", g_config.keepalive_timeout);
    DBG("buffer_size:        %u\n", g_config.buffer_size);
    DBG("send_bytes_per_sec: %u\n", g_config.send_bytes_per_sec);
    DBG("fec_group_size:     %u\n", g_config.fec_group_size);
    DBG("udp_timeout:        %u\n", g_config.udp_timeout);
    DBG("max_rtt:            %u\n", g_config.max_rtt);
    DBG("min_rtt:            %u\n", g_config.min_rtt);
    DBG("timeout_rtt_ratio:  %.2f\n", g_config.timeout_rtt_ratio);
    DBG("ack_size:           %u\n", g_config.ack_size);
    DBG("tcp_nodelay:        %u\n", g_config.tcp_nodelay);

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
    int ret = 0;
    long fsize = 0;
    int nread;
    unsigned int i;
    static allow_access_t temp_allow_list[MAX_PORT_NUM + 1];
    static listen_port_t temp_listen_list[MAX_PORT_NUM + 1];
    FILE *f = fopen(conf_name, "rb");
    if (NULL == f) {
        LOG("ReloadConf: Config file %s open failed!\n", conf_name);
        ret = -1;
        goto errout;
    }
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize >= MAX_CONF_SIZE) {
        LOG("ReloadConf: Config file too large\n");
        ret = -1;
        goto errout;
    }

    strncpy(conf_name, conf_name, MAX_CONF_NAME_LENGTH - 1);
    buf = (char *)malloc(fsize + 1);
    if (NULL == buf) {
        LOG("ReloadConf: Alloc memory failed\n");
        ret = -1;
        goto errout;
    }
    nread = fread(buf, fsize, 1, f);
    if (!nread) {
        LOG("ReloadConf: Failed to read config file\n");
        ret = -1;
        goto errout;
    }

    buf[fsize] = '\0';
    fclose(f);

    bzero(&settings, sizeof(json_settings));
    obj = json_parse_ex(&settings, buf, fsize, error_buf);
    if (NULL == obj) {
        LOG("ReloadConf: json_parse: %s\n", error_buf);
        ret = -2;
        goto errout;
    }

    CHECK_OBJECT_TYPE(obj->type, json_object);

    bzero(&temp_allow_list, sizeof(temp_allow_list));
    bzero(&temp_listen_list, sizeof(temp_listen_list));
    for (i = 0; i < obj->u.object.length; i++) {
        char *name = obj->u.object.values[i].name;
        json_value *value = obj->u.object.values[i].value;

        if (!strcmp(name, "allow_list")) {
            unsigned int j, k;
            CHECK_OBJECT_TYPE(value->type, json_array);
            for (j = 0; j < value->u.array.length; j++) {
                json_value *v = value->u.array.values[j];
                if (j >= MAX_PORT_NUM)
                    break;
                CHECK_OBJECT_TYPE(v->type, json_object);
                for (k = 0; k < v->u.object.length; k++) {
                    char *sub_name = v->u.object.values[k].name;
                    json_value *sub_value = v->u.object.values[k].value;
                    if (!strcmp(sub_name, "map_id")) {
                        CHECK_OBJECT_TYPE(sub_value->type, json_integer);
                        temp_allow_list[j].map_id = sub_value->u.integer;
                    } else if (!strcmp(sub_name, "target_addr")) {
                        char *ptr = sub_value->u.string.ptr;
                        CHECK_OBJECT_TYPE(sub_value->type, json_string);
                        if (sub_value->u.string.length >= ADDRESS_MAX_LEN) {
                            ret = -2;
                            goto errout;
                        }

                        strncpy(temp_allow_list[j].target_addr, ptr,
                                ADDRESS_MAX_LEN);
                    } else if (!strcmp(sub_name, "target_port")) {
                        CHECK_OBJECT_TYPE(sub_value->type, json_integer);
                        temp_allow_list[j].target_port
                            = sub_value->u.integer;
                    } else if (!strcmp(sub_name, "protocol")) {
                        CHECK_OBJECT_TYPE(sub_value->type, json_string);
                        char *ptr = sub_value->u.string.ptr;
                        if (!strcasecmp(ptr, "tcp")) {
                            temp_allow_list[j].protocol = PROTOCOL_TCP;
                        } else if (!strcasecmp(ptr, "udp")) {
                            temp_allow_list[j].protocol = PROTOCOL_UDP;
                        } else {
                            LOG("protocol not support: %s\n", ptr);
                            ret = -1;
                            goto errout;
                        }
                    }
                }
            }
        } else if (!strcmp(name, "listen_list")) {
            unsigned int j, k;
            CHECK_OBJECT_TYPE(value->type, json_array);
            for (j = 0; j < value->u.array.length; j++) {
                json_value *v = value->u.array.values[j];
                if (j >= MAX_PORT_NUM)
                    break;
                CHECK_OBJECT_TYPE(v->type, json_object);
                for (k = 0; k < v->u.object.length; k++) {
                    char *sub_name = v->u.object.values[k].name;
                    json_value *sub_value = v->u.object.values[k].value;
                    if (!strcmp(sub_name, "local_port")) {
                        CHECK_OBJECT_TYPE(sub_value->type, json_integer);
                        temp_listen_list[j].local_port
                            = sub_value->u.integer;
                    } else if (!strcmp(sub_name, "map_id")) {
                        CHECK_OBJECT_TYPE(sub_value->type, json_integer);
                        temp_listen_list[j].map_id = sub_value->u.integer;
                    } else if (!strcmp(sub_name, "protocol")) {
                        CHECK_OBJECT_TYPE(sub_value->type, json_string);
                        char *ptr = sub_value->u.string.ptr;
                        if (!strcasecmp(ptr, "tcp")) {
                            temp_listen_list[j].protocol = PROTOCOL_TCP;
                        } else if (!strcasecmp(ptr, "udp")) {
                            temp_listen_list[j].protocol = PROTOCOL_UDP;
                        } else {
                            LOG("protocol not support: %s\n", ptr);
                            ret = -2;
                            goto errout;
                        }
                    }
                }
            }
        }
    }

    if (ret == 0) {
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
    g_config.debug_log = 1;
    strncpy(g_config.map_bind_addr, "0.0.0.0", ADDRESS_MAX_LEN);
    strncpy(g_config.flow_local_addr, "0.0.0.0", ADDRESS_MAX_LEN);
    g_config.flow_local_port    = 0;
    bzero(g_config.flow_remote_addr, DOMAIN_MAX_LEN);
    g_config.flow_remote_port   = 19210;
    bzero(g_config.dns_server_addr, ADDRESS_MAX_LEN);
    g_config.keepalive_timeout  = 300;
    g_config.buffer_size        = 20 * 1024 * 1024;
    g_config.send_bytes_per_sec = 8 * 1024 * 1024;
    g_config.fec_group_size     = 0;
    g_config.udp_timeout        = 60;
    g_config.max_rtt            = 1000;
    g_config.min_rtt            = 150;
    g_config.timeout_rtt_ratio  = 1.7;
    g_config.ack_size           = 100;
    g_config.tcp_nodelay        = 0;
    bzero(g_config.allow_list, sizeof(g_config.allow_list));
    bzero(g_config.listen_list, sizeof(g_config.listen_list));
}
