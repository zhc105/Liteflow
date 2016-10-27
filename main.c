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

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "config.h"
#include "util.h"
#include "liteflow.h"

#define RVERSION "0.2.6"
#ifdef ENABLE_LITEDT_CHECKSUM
    #define VERSION RVERSION"-chk"
#else
    #define VERSION RVERSION
#endif

int main(int argc, char *argv[])
{
    int ret = 0;
    static char config_name[256];

    if (argc > 1 && !strcmp(argv[1], "--version")) {
        printf("Liteflow %s by Moonflow\n", VERSION);
        return 0;
    }

    signal(SIGPIPE, SIG_IGN);

    snprintf(config_name, sizeof(config_name), "%s.conf", argv[0]);
    global_config_init();
    load_config_file(config_name);

    ret = init_liteflow();
    if (ret != 0) {
        LOG("liteflow init failed!\n");
        return ret;
    }

    start_liteflow();

    return 0;
}
