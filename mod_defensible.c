/*
 * mod_defensible.c - Forbid page access using DNSBL
 *
 * Copyright © 2007 Julien Danjou <julien@danjou.info>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <config.h>

#include "apr_strings.h"

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#ifdef HAVE_UDNS
#include <udns.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#else
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "mod_defensible.h"

#define DEFENSIBLE_HEADER_STRING "mod_defensible/" DEFENSIBLE_VERSION

#ifdef HAVE_UDNS
char * blacklisted_by = NULL;
int curq = 0;
#endif

enum use_dnsbl_type
{
    T_YES,
    T_NO
};

typedef struct
{
    enum use_dnsbl_type use_dnsbl;
    apr_array_header_t *dnsbl_servers;
} dnsbl_config;

module AP_MODULE_DECLARE_DATA defensible_module;

static const char *use_dnsbl(cmd_parms *parms __attribute__ ((unused)),
                             void *mconfig,
                             const char *arg)
{
    dnsbl_config *s_cfg = (dnsbl_config *) mconfig;

    if(!strcasecmp(arg, "On"))
        s_cfg->use_dnsbl = T_YES;
    else
        s_cfg->use_dnsbl = T_NO;

    return NULL;
}

static const char *set_dnsbl_server(cmd_parms *parms,
                                    void *mconfig,
                                    const char *server_o)
{
    char *server = apr_pstrdup(parms->pool, server_o);
    char ** cfg;
    dnsbl_config *s_cfg = (dnsbl_config *) mconfig;

    cfg = (char **) apr_array_push(s_cfg->dnsbl_servers);
    *cfg = server;

    return NULL;
}

static const command_rec defensible_cmds[] =
{
    AP_INIT_TAKE1("DnsblUse", use_dnsbl, NULL, RSRC_CONF,
                  "'On' to use DNSBL"),
    AP_INIT_ITERATE("DnsblServers", set_dnsbl_server, NULL, RSRC_CONF,
                     "DNS suffix to use for lookup"),
    {NULL, {NULL}, NULL, 0, RAW_ARGS, NULL}
};

static void *create_defensible_config(apr_pool_t *p,
                                 char *dummy __attribute__ ((unused)))
{
    dnsbl_config *conf = (dnsbl_config *) apr_pcalloc(p, sizeof(dnsbl_config)); 

    conf->use_dnsbl = T_NO;
    conf->dnsbl_servers = apr_array_make(p, 1, sizeof(char *)); 

    return (void *) conf;
}

#ifdef HAVE_UDNS
static void udns_cb(struct dns_ctx *ctx __attribute__ ((unused)),
                    struct dns_rr_a4 *r,
                    void *data)
{
    if(r)
        blacklisted_by = (char *) data;
    curq--;

    return;
}
#endif


static int check_dnsbl(request_rec *r)
{
    char **srv_elts;
    char *ip = NULL;
    int i;

    dnsbl_config *conf = (dnsbl_config *)
        ap_get_module_config(r->per_dir_config, &defensible_module);

    /* Return right now if we don't use DNSBL */
    if(conf->use_dnsbl == T_NO)
        return 0;

    ip = r->connection->remote_ip;

    /* Return if IPv6 client */
    if (ap_strchr_c(ip, ':'))
       return 0;

    srv_elts = (char **) conf->dnsbl_servers->elts;

#ifdef HAVE_UDNS
    dns_init(1);
#else
    int old_i, j, k = 0; 
    ssize_t len, len_dnsbl;
    char *revip = NULL, *hostdnsbl = NULL;
    len = strlen(ip); 

    revip  = (char *) apr_pcalloc(r->pool, sizeof(char) * (len + 1)); 

    /* reverse IP */
    old_i = len; 
    for(i = len - 1; i >= 0; i--) 
        if(ip[i] == '.' || i == 0) 
        { 
            for(j = i ? i + 1 : 0; j < old_i; j++) 
                revip[k++] = ip[j]; 
            revip[k++] = '.'; 
            old_i = i; 
        }
#endif

    /* check in each dnsbl */
    for(i = 0; i < conf->dnsbl_servers->nelts; i++)
    {
#ifdef HAVE_UDNS
        struct in_addr client_addr;
        inet_aton(ip, &client_addr);
        dns_submit_a4dnsbl(0, &client_addr, srv_elts[i], udns_cb, srv_elts[i]);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "looking up in DNSBL: %s for: %s", srv_elts[i], r->uri);
#else
        len_dnsbl = strlen(srv_elts[i]);

        hostdnsbl = (char *) apr_pcalloc(r->pool, sizeof(char) * (len_dnsbl + len + 2)); 

        strncpy(hostdnsbl, revip, len);
        strncat(hostdnsbl, ".", 1);
        strncat(hostdnsbl, srv_elts[i], len_dnsbl);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "looking up in DNSBL: %s for: %s", srv_elts[i], r->uri);

        if(gethostbyname(hostdnsbl))
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "denied by DNSBL: %s for: %s", srv_elts[i], r->uri);
            return 1;
        }
        else
        {
            switch(h_errno)
            {
                case HOST_NOT_FOUND:
                case NO_ADDRESS:
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "client not listed on %s",
                                  srv_elts[i]);
                    break;
                case NO_RECOVERY:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "non-recoverable DNS error while checking DNSBL on %s for %s",
                                  srv_elts[i], r->uri);
                    break;
                case TRY_AGAIN:
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "temporary DNS error while checking DNSBL on %s for %s",
                                  srv_elts[i], r->uri);
                    break;
            }
        }
#endif
    }

#ifdef HAVE_UDNS
    struct pollfd pfd;
    pfd.fd = dns_sock(0);
    pfd.events = POLLIN;
    while(curq && !blacklisted_by)
    {
        dns_timeouts(0, -1, 0);
        if(poll(&pfd, 1, 1000))
            dns_ioevent(0, 0);
    }
    if(blacklisted_by)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "denied by DNSBL: %s for: %s", srv_elts[i], r->uri);
        return 1;
    }
    else
    {
        for(i = 0; i < conf->dnsbl_servers->nelts; i++)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "client not listed on %s",
                          srv_elts[i]);
    }
#endif

    return 0;
}

static int check_dnsbl_access(request_rec *r)
{
    int ret = OK;

    if (check_dnsbl(r))
        ret = HTTP_FORBIDDEN;

    return ret;
}

static int defensible_init(apr_pool_t *p,
                       apr_pool_t *plog __attribute__ ((unused)),
                       apr_pool_t *ptemp __attribute__ ((unused)),
                       server_rec *s __attribute__ ((unused)))
{
    ap_add_version_component(p, DEFENSIBLE_HEADER_STRING);

    return OK;
}

static void register_hooks(apr_pool_t *p __attribute__ ((unused)))
{
    ap_hook_access_checker(check_dnsbl_access, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(defensible_init, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA defensible_module =
{
    STANDARD20_MODULE_STUFF,
    create_defensible_config,   /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    defensible_cmds,
    register_hooks              /* register hooks */
};
