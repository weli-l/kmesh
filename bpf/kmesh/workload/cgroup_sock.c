/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Author: kwb0523
 * Create: 2024-01-20
 */

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include "bpf_log.h"
#include "ctx/sock_addr.h"
#include "frontend.h"
#include "bpf_common.h"

static inline int sock4_traffic_control(struct bpf_sock_addr *ctx)
{
    int ret;
    frontend_value *frontend_v = NULL;

    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    DECLARE_FRONTEND_KEY(ctx, frontend_k);

    DECLARE_VAR_IPV4(ctx->user_ip4, ip);
    BPF_LOG(DEBUG, KMESH, "origin addr=[%pI4h:%u]\n", &ip, bpf_ntohs(ctx->user_port));
    frontend_v = map_lookup_frontend(&frontend_k);
    if (!frontend_v) {
        return -ENOENT;
    }

    BPF_LOG(DEBUG, KMESH, "bpf find frontend addr=[%pI4h:%u]\n", &ip, bpf_ntohs(ctx->user_port));
    ret = frontend_manager(ctx, frontend_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, KMESH, "frontend_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx)
{
    if (handle_kmesh_manage_process(ctx) || !is_kmesh_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    if (handle_bypass_process(ctx) || is_bypass_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    int ret = sock4_traffic_control(ctx);

    return CGROUP_SOCK_OK;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;