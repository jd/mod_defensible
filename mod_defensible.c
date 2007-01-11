/*
 * mod_defensible.c - © Julien Danjou <julien@danjou.info>
 *
 * Allow blacklisting using DNSBL/RBL
 *
 */

#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_md5.h"

#define APR_WANT_STRFUNC
#define APR_WANT_BYTEFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#include <netinet/in.h>
#include <netdb.h>

#include "mod_defensible.h"

#define DEFENSIBLE_HEADER_STRING "mod_defensible/" DEFENSIBLE_VERSION

enum use_dnsbl_type {
    T_YES,
    T_NO
};

typedef struct {
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
    {NULL, NULL, NULL, NULL, RAW_ARGS, NULL}
};

static void *create_defensible_config(apr_pool_t *p,
                                 char *dummy __attribute__ ((unused)))
{
    dnsbl_config *conf = (dnsbl_config *) apr_pcalloc(p, sizeof(dnsbl_config)); 

    conf->use_dnsbl = T_NO;
    conf->dnsbl_servers = apr_array_make(p, 1, sizeof(char *)); 

    return (void *) conf;
}

static int check_dnsbl(request_rec *r)
{
    int i, old_i, j, k = 0; 
    ssize_t len, len_dnsbl;
    char *revip = NULL, *ip = NULL, *hostdnsbl = NULL;
    char **srv_elts;

    dnsbl_config *conf = (dnsbl_config *)
        ap_get_module_config(r->per_dir_config, &defensible_module);

    /* Return right now if we don't use DNSBL */
    if(conf->use_dnsbl == T_NO)
        return 0;

    ip = r->connection->remote_ip;

    /* Return if IPv6 client */
    if (ap_strchr_c(ip, ':'))
       return 0;

    len = strlen(ip); 

    srv_elts = (char **) conf->dnsbl_servers->elts;

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

    /* check in each dnsbl */
    for(i = 0; i < conf->dnsbl_servers->nelts; i++)
    {
        len_dnsbl = strlen(srv_elts[i]);

        hostdnsbl = (char *) apr_pcalloc(r->pool, sizeof(char) * (len_dnsbl + len + 2)); 

        strncpy(hostdnsbl, revip, len);
        strncat(hostdnsbl, ".", 1);
        strncat(hostdnsbl, srv_elts[i], len_dnsbl);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "looking up in DNSBL: %s for: %s", srv_elts[i], r->uri);

        if(hostdnsbl && gethostbyname(hostdnsbl))
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "denied by DNSBL: %s for: %s", srv_elts[i], r->uri);
            return 1;
        }
    }

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
    create_defensible_config,        /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    defensible_cmds,
    register_hooks              /* register hooks */
};
