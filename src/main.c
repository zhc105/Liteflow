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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <argp.h>

#include "config.h"
#include "util.h"
#include "liteflow.h"
#include "version.h"

#define VERSION_MAX_SIZE 256
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif // PATH_MAX

static char program_version[VERSION_MAX_SIZE];
const char *argp_program_version = NULL;
const char *argp_program_bug_address = "<me@zhc105.net>";
const char doc[] = "UDP tunnel & TCP/UDP Port forwarding";
static struct argp_option options[] = {
    {"config", 'c', "CONFIG_FILE", 0,
        "Specify the config file path. If not specified, the default value is <exe_name>.conf.", 0},
    {"test-config", 't', NULL, 0,
        "Test the config file and exit.", 0},
    {0}
};

static char config_name[PATH_MAX] = { 0 };
static bool test_mode = false;

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    int ret;
    (void)state;
    switch (key) {
        case 'c':
            strncpy(config_name, arg, sizeof(config_name) - 1);
            break;
        case 't':
            test_mode = true;
            break;
        case ARGP_KEY_ARG:
            LOG("Invalid parameter %s.", arg);
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, NULL, doc };

int main(int argc, char *argv[])
{
    int ret = 0;

    // The config file path is set to <exe_name>.conf by default.
    snprintf(config_name, sizeof(config_name), "%s.conf", argv[0]);
    snprintf(program_version, sizeof(program_version), "%s", liteflow_version);
    argp_program_version = program_version;

    global_config_init();

    argp_parse(&argp, argc, argv, 0, 0, NULL);

    srand(time(NULL));
    signal(SIGPIPE, SIG_IGN);

    if(test_mode) {
        LOG("Validating liteflow config file %s.", config_name);
    }

    ret = load_config_file(config_name);

    if(test_mode) {
        if (NO_ERROR == ret) {
            LOG("Config file %s is valid.", config_name);
        } else {
            LOG("Config file %s has mistake and please check the error message.",
                config_name);
        }

        return ret;
    } else if (NO_ERROR != ret) {
        LOG("liteflow config file %s loading failed!", config_name);
        return ret;
    }

    ret = init_liteflow();
    if (ret != 0) {
        LOG("liteflow init failed!");
        return ret;
    }

    start_liteflow();

    return 0;
}
