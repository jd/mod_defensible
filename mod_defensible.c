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
#include "http_protocol.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#ifdef HAVE_LIBUDNS
#include <udns.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#else
#include <netinet/in.h>
#include <netdb.h>
#endif

#define DEFENSIBLE_HEADER_STRING "mod_defensible/" VERSION

/* enum used for config */
enum use_dnsbl_type
{
    T_YES,
    T_NO
};

/*
 * module configuration structure
 * use_dnsbl is T_YES or T_NO if we use it or not
 * dnsbl_servers is an array containing DNSBL servers
 */
typedef struct
{
    enum use_dnsbl_type use_dnsbl;
    apr_array_header_t *dnsbl_servers;
#ifdef HAVE_LIBUDNS
    char * nameserver;
#endif
} dnsbl_config;

module AP_MODULE_DECLARE_DATA defensible_module;

/* Callback function called when we get DnsblUse option */
static const char *use_dnsbl(cmd_parms *parms __attribute__ ((unused)),
                             void *mconfig,
                             const char *arg)
{
    dnsbl_config *s_cfg = (dnsbl_config *) mconfig;
    
    /* Repeat after me: DNSBL is good for your web server */
    if(!strcasecmp(arg, "On"))
        s_cfg->use_dnsbl = T_YES;
    /* Oh, no ! © Lemmings */
    else
        s_cfg->use_dnsbl = T_NO;

    return NULL;
}

#ifdef HAVE_LIBUDNS
/* Callback function called when we get DnsblNameserver option */
static const char *set_dnsbl_nameserver(cmd_parms *parms,
                             void *mconfig,
                             const char *arg)
{
    dnsbl_config *s_cfg = (dnsbl_config *) mconfig;
    
    s_cfg->nameserver = apr_pstrdup(parms->pool, arg);

    return NULL;
}
#endif

/* Callback function called when we get DnsblServers option */
static const char *set_dnsbl_server(cmd_parms *parms,
                                    void *mconfig,
                                    const char *server_o)
{
    char *server = apr_pstrdup(parms->pool, server_o);
    char ** cfg;
    dnsbl_config *s_cfg = (dnsbl_config *) mconfig;

    /* We add the DNSBL server to the array */
    cfg = (char **) apr_array_push(s_cfg->dnsbl_servers);
    *cfg = server;

    return NULL;
}

/* Configuration directive declaration for our module */
static const command_rec defensible_cmds[] =
{
    AP_INIT_TAKE1("DnsblUse", use_dnsbl, NULL, RSRC_CONF|ACCESS_CONF|OR_LIMIT,
                  "Set to 'On' to use DNSBL"),
    AP_INIT_ITERATE("DnsblServers", set_dnsbl_server, NULL, RSRC_CONF|ACCESS_CONF|OR_LIMIT,
                     "DNS suffix to use for lookup in DNSBL server"),
#ifdef HAVE_LIBUDNS
    AP_INIT_TAKE1("DnsblNameserver", set_dnsbl_nameserver, NULL, RSRC_CONF|ACCESS_CONF|OR_LIMIT,
                  "IP address of the nameserver to use for DNSBL lookup"),
#endif
    {NULL, {NULL}, NULL, 0, RAW_ARGS, NULL}
};

/* Create initial configuration */
static void *create_defensible_config(apr_pool_t *p,
                                 char *dummy __attribute__ ((unused)))
{
    dnsbl_config *conf = (dnsbl_config *) apr_pcalloc(p, sizeof(dnsbl_config)); 

    conf->use_dnsbl = T_NO;
    conf->dnsbl_servers = apr_array_make(p, 1, sizeof(char *)); 

#ifdef HAVE_LIBUDNS
    conf->nameserver = NULL;
#endif

    return (void *) conf;
}

#ifdef HAVE_LIBUDNS
/* Struct used as data for the udns callback function */
struct udns_cb_data
{
    request_rec *r;
    char * dnsbl;
    int blacklist;
};

/* udns callback function called by udns after each query resolution */
static void udns_cb(struct dns_ctx *ctx __attribute__ ((unused)),
                    struct dns_rr_a4 *r,
                    void *data)
{
    struct udns_cb_data * info = (struct udns_cb_data *) data;

    /* If we get a record */
    if(r)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, info->r,
                      "client denied by DNSBL: %s for: %s",
                      info->dnsbl, info->r->uri);
        free(r);
        info->blacklist = 1;
    }
    else
    {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, info->r,
                      "client not listed on %s",
                      info->dnsbl);
    }

    return;
}
#endif

static void generate_page(request_rec *r, char * dnsbl)
{
    ap_set_content_type(r, "text/html"); 
    ap_rputs(DOCTYPE_HTML_2_0, r);
    ap_rputs("<html><head>\n<title>403 Forbidden</title></head><body><h1>Forbidden</h1>\n", r);
    ap_rprintf(r, "<p>You don't have permission to access %s\n", ap_escape_html(r->pool, r->uri));
    ap_rprintf(r, "on this server because you are currently blacklisted by a DNSBL server at: <b>%s</b></p>\n", dnsbl);
    ap_rputs("<hr>\n", r);
    ap_rprintf(r, "<address>%s</address>\n", ap_get_server_version());
    ap_rputs("</body></html>\n", r);
}

/* 
 * Callback function called on each HTTP request
 * Check an IP in a DNSBL
 */
static int check_dnsbl_access(request_rec *r)
{
    char **srv_elts;
    char *ip = r->connection->remote_ip;
    int i;

    dnsbl_config *conf = (dnsbl_config *)
        ap_get_module_config(r->per_dir_config, &defensible_module);

    /* Return right now if we don't use DNSBL */
    if(conf->use_dnsbl == T_NO)
        return DECLINED;

    /* Return if IPv6 client */
    if (ap_strchr_c(ip, ':'))
       return DECLINED;

    srv_elts = (char **) conf->dnsbl_servers->elts;

#ifdef HAVE_LIBUDNS
    apr_array_header_t *data_array;
    data_array = apr_array_make(r->pool, 1, sizeof(struct udns_cb_data *)); 

    /* Initialize udns lib */
    if(dns_init(&dns_defctx, 0) < 0)
    {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      "error initializing udns library for DNSBL, can't check client");
        return DECLINED;
    }

    /* Add configured nameserver if available */
    if(conf->nameserver)
        dns_add_serv(&dns_defctx, NULL);
        if(dns_add_serv(&dns_defctx, conf->nameserver) < 0)
        {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                          "error adding DNSBL nameserver, can't check client");
            return DECLINED;
        }

    if(dns_open(&dns_defctx) < 0)
    {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      "error open connection from udns library for DNSBL, can't check client");
        return DECLINED;
    }
#else
    int old_i, j, k = 0; 
    ssize_t len, len_dnsbl;
    char *revip = NULL, *hostdnsbl = NULL;
    len = strlen(ip); 

    revip  = (char *) apr_pcalloc(r->pool, sizeof(char) * (len + 1)); 

    /* reverse IP from a.b.c.d to d.c.b.a */
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
#ifdef HAVE_LIBUDNS
        struct in_addr client_addr;
        struct udns_cb_data *data, **tmp;
        
        /* First, allocate space for udns_cb_data in data */
        data = (struct udns_cb_data *) apr_pcalloc (r->pool, sizeof(struct udns_cb_data));

        /* Copy connection_req and our DNSBL server in data */
        data->r = r;
        data->dnsbl = srv_elts[i];
        data->blacklist = 0;

        /* Finally push data in our array */
        tmp = (struct udns_cb_data **) apr_array_push(data_array);
        *tmp = data;

        /*
         * Submit a DNSBL query to udns with:
         * Client address, DNSBL server, udns_cb as callback function
         * and data as data for the callback function
         */
        inet_aton(ip, &client_addr);
        dns_submit_a4dnsbl(&dns_defctx, &client_addr, srv_elts[i], udns_cb, data);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "looking up in DNSBL: %s for: %s", srv_elts[i], r->uri);
#else
        /* 
         * Here we build the host to lookup:
         * revip.dnsblserver
         */
        len_dnsbl = strlen(srv_elts[i]);

        hostdnsbl = (char *) apr_pcalloc(r->pool, sizeof(char) * (len_dnsbl + len + 2)); 

        strncpy(hostdnsbl, revip, len);
        strncat(hostdnsbl, ".", 1);
        strncat(hostdnsbl, srv_elts[i], len_dnsbl);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "looking up in DNSBL: %s for: %s", srv_elts[i], r->uri);

        /* If it resolve, the IP is blacklisted */
        if(gethostbyname(hostdnsbl))
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "denied by DNSBL: %s for: %s", srv_elts[i], r->uri);
            r->status = 403;
            generate_page(r, srv_elts[i]);
            return DONE;
        }
        else
        {
            /* Log some interesting stuff if we don't have any record */
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

#ifdef HAVE_LIBUDNS
    struct pollfd pfd;
    struct udns_cb_data **data_array_elts;

    pfd.fd = dns_sock(0);
    pfd.events = POLLIN;

    data_array_elts = (struct udns_cb_data **) data_array->elts;

    /* While we have a queue active */
    while(dns_active(&dns_defctx))
        if(poll(&pfd, 1, dns_timeouts(0, -1, 0) * 1000))
            dns_ioevent(0, 0);

    dns_close(&dns_defctx);
    dns_free(&dns_defctx);

    /* Check if one of the DNSBL server has blacklisted */
    for(i = 0; i < data_array->nelts; i++)
        if(data_array_elts[i]->blacklist)
        {
            r->status = 403;
            generate_page(r, data_array_elts[i]->dnsbl);
            return DONE;
        }
#endif

    return OK;
}

/* Callback function used for initialization */
static int defensible_init(apr_pool_t *p,
                       apr_pool_t *plog __attribute__ ((unused)),
                       apr_pool_t *ptemp __attribute__ ((unused)),
                       server_rec *s __attribute__ ((unused)))
{
    ap_add_version_component(p, DEFENSIBLE_HEADER_STRING);

    return OK;
}

/* Register hooks */
static void register_hooks(apr_pool_t *p __attribute__ ((unused)))
{
    ap_hook_access_checker(check_dnsbl_access, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(defensible_init, NULL, NULL, APR_HOOK_LAST);
}

/* Declare our module to apache2 */
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
