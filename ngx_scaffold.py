#! /usr/bin/env python

import argparse
import string
import re

ngx_content_handler_config = """
ngx_addon_name=ngx_http_@name_module
HTTP_MODULES="$HTTP_MODULES ngx_http_@name_module"
NGX_ADDON_SRCS="$NGX_ADDON_SRCS $ngx_addon_dir/ngx_http_@name_module.c"
"""

ngx_content_handler_template = """

/*
 * Copyright (C) Simon Liu, http://www.pagefault.info
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


@preConfDeclare
@postConfDeclare
@createMainDeclare
@initMainDeclare
@createSrvDeclare
@mergeSrvDeclare
@createLocDeclare
@mergeLocDeclare


static char *ngx_http_@name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_@name_commands[] = {

    { ngx_string("@name"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_@name,
      0,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_@name_module_ctx = {
    @preConfName,      /* preconfiguration */
    @postConfName,     /* postconfiguration */

    @createMainName,     /* create main configuration */
    @initMainName,       /* init main configuration */

    @createSrvName,      /* create server configuration */
    @mergeSrvName,       /* merge server configuration */

    @createLocName,      /* create location configuration */
    @mergeLocName        /* merge location configuration */
};


ngx_module_t  ngx_http_@name_module = {
    NGX_MODULE_V1,
    &ngx_http_@name_module_ctx,    /* module context */
    ngx_http_@name_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_@name_handler(ngx_http_request_t *r)
{
    return NGX_OK;
}


static char *
ngx_http_@name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_@name_handler;

    return NGX_CONF_OK;
}


@preConfDefine


@postConfDefine


@createMainDefine


@initMainDefine


@createSrvDefine


@mergeSrvDefine


@createLocDefine


@mergeLocDefine


"""


ngx_filter_module_config = """
ngx_addon_name=ngx_http_@name_filter_module
HTTP_AUX_FILTER_MODULES="$HTTP_AUX_FILTER_MODULES ngx_http_@name_filter_module"
NGX_ADDON_SRCS="$NGX_ADDON_SRCS $ngx_addon_dir/ngx_http_@name_filter_module.c"
"""

ngx_filter_module_template = """

/*
 * Copyright (C) Simon Liu, http://www.pagefault.info
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


@preConfDeclare
@createMainDeclare
@initMainDeclare
@createSrvDeclare
@mergeSrvDeclare
@createLocDeclare
@mergeLocDeclare


static ngx_int_t  ngx_http_@name_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_@name_filter_commands[] = {

    ngx_null_command
};


static ngx_http_module_t  ngx_http_@name_filter_module_ctx = {
    @preConfName,      /* preconfiguration */
    ngx_http_@name_filter_init,     /* postconfiguration */

    @createMainName,     /* create main configuration */
    @initMainName,       /* init main configuration */

    @createSrvName,      /* create server configuration */
    @mergeSrvName,       /* merge server configuration */

    @createLocName,      /* create location configuration */
    @mergeLocName        /* merge location configuration */
};


ngx_module_t  ngx_http_@name_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_@name_filter_module_ctx,       /* module context */
    ngx_http_@name_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;


static ngx_int_t
ngx_http_@name_header_filter(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_@name_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
   return ngx_http_next_body_filter(r, in);
}


@preConfDefine


@createMainDefine


@initMainDefine


@createSrvDefine


@mergeSrvDefine


@createLocDefine


@mergeLocDefine


static ngx_int_t
ngx_http_@name_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_@name_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter  = ngx_http_@name_body_filte;
    return NGX_OK;
}


"""

ngx_upstream_template = """

/*
 * Copyright (C) Simon Liu, http://www.pagefault.info
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_upstream_conf_t       upstream;

#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif
} ngx_http_@name_loc_conf_t;


typedef struct {
} ngx_http_@name_ctx_t;


#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_@name_create_key(ngx_http_request_t *r);
#endif
static ngx_int_t ngx_http_@name_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_@name_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_@name_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_@name_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_@name_input_filter_init(void *data);
static ngx_int_t ngx_http_@name_copy_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static void ngx_http_@name_abort_request(ngx_http_request_t *r);
static void ngx_http_@name_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);


@preConfDeclare
@postConfDeclare
@createMainDeclare
@initMainDeclare
@createSrvDeclare
@mergeSrvDeclare
static void *ngx_http_@name_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_@name_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static char *ngx_http_@name_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_@name_store(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#if (NGX_HTTP_CACHE)
static char *ngx_http_@name_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_@name_cache_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#endif

static char *ngx_http_@name_lowat_check(ngx_conf_t *cf, void *post, void *data);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_@name_set_ssl(ngx_conf_t *cf,
    ngx_http_@name_loc_conf_t *plcf);
#endif

static ngx_conf_post_t  ngx_http_@name_lowat_post =
    { ngx_http_@name_lowat_check };


static ngx_conf_bitmask_t  ngx_http_@name_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_@name_commands[] = {

    { ngx_string("@name_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_@name_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("@name_store"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_@name_store,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("@name_store_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.store_access),
      NULL },

    { ngx_string("@name_buffering"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.buffering),
      NULL },

    { ngx_string("@name_ignore_client_abort"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { ngx_string("@name_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("@name_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("@name_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("@name_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.send_lowat),
      &ngx_http_@name_lowat_post },

    { ngx_string("@name_intercept_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.intercept_errors),
      NULL },

    { ngx_string("@name_pass_request_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { ngx_string("@name_pass_request_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.pass_request_body),
      NULL },

    { ngx_string("@name_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("@name_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("@name_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.bufs),
      NULL },

    { ngx_string("@name_busy_buffers_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

#if (NGX_HTTP_CACHE)

    { ngx_string("@name_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_@name_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("@name_cache_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_@name_cache_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("@name_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_file_cache_set_slot,
      0,
      0,
      &ngx_http_@name_module },

    { ngx_string("@name_cache_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.cache_bypass),
      NULL },

    { ngx_string("@name_no_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.no_cache),
      NULL },

    { ngx_string("@name_cache_valid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_file_cache_valid_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.cache_valid),
      NULL },

    { ngx_string("@name_cache_min_uses"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { ngx_string("@name_cache_use_stale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.cache_use_stale),
      &ngx_http_@name_next_upstream_masks },

    { ngx_string("@name_cache_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.cache_methods),
      &ngx_http_upstream_cache_method_mask },

    { ngx_string("@name_cache_lock"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.cache_lock),
      NULL },

    { ngx_string("@name_cache_lock_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

#endif

    { ngx_string("@name_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.temp_path),
      NULL },

    { ngx_string("@name_max_temp_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { ngx_string("@name_temp_file_write_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { ngx_string("@name_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.next_upstream),
      &ngx_http_@name_next_upstream_masks },

    { ngx_string("@name_pass_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.pass_headers),
      NULL },

    { ngx_string("@name_hide_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.hide_headers),
      NULL },

    { ngx_string("@name_ignore_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_@name_loc_conf_t, upstream.ignore_headers),
      &ngx_http_upstream_ignore_headers_masks },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_@name_module_ctx = {
    @preConfName,      /* preconfiguration */
    @postConfName,     /* postconfiguration */

    @createMainName,     /* create main configuration */
    @initMainName,       /* init main configuration */

    @createSrvName,      /* create server configuration */
    @mergeSrvName,       /* merge server configuration */

    ngx_http_@name_create_loc_conf,           /* create location configration */
    ngx_http_@name_merge_loc_conf             /* merge location configration */
};


ngx_module_t  ngx_http_@name_module = {
    NGX_MODULE_V1,
    &ngx_http_@name_module_ctx,            /* module context */
    ngx_http_@name_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_@name_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};


#if (NGX_HTTP_CACHE)

static ngx_keyval_t  ngx_http_@name_cache_headers[] = {
    { ngx_string("Host"), ngx_string("$@name_host") },
    { ngx_string("Connection"), ngx_string("close") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_string("If-Modified-Since"), ngx_string("") },
    { ngx_string("If-Unmodified-Since"), ngx_string("") },
    { ngx_string("If-None-Match"), ngx_string("") },
    { ngx_string("If-Match"), ngx_string("") },
    { ngx_string("Range"), ngx_string("") },
    { ngx_string("If-Range"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};

#endif


static ngx_path_init_t  ngx_http_@name_temp_path = {
    ngx_string(NGX_HTTP_@name_TEMP_PATH), { 1, 2, 0 }
};


static ngx_int_t
ngx_http_@name_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_@name_ctx_t       *ctx;
    ngx_http_@name_loc_conf_t  *plcf;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_@name_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_@name_module);

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_@name_module);

    u = r->upstream;

    if (plcf->@name_lengths == NULL) {
        ctx->vars = plcf->vars;
        u->schema = plcf->vars.schema;
    } else {
        if (ngx_http_@name_eval(r, ctx, plcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (ngx_buf_tag_t) &ngx_http_@name_module;

    u->conf = &plcf->upstream;

#if (NGX_HTTP_CACHE)
    u->create_key = ngx_http_@name_create_key;
#endif
    u->create_request = ngx_http_@name_create_request;
    u->reinit_request = ngx_http_@name_reinit_request;
    u->process_header = ngx_http_@name_process_status_line;
    u->abort_request = ngx_http_@name_abort_request;
    u->finalize_request = ngx_http_@name_finalize_request;
    r->state = 0;

    u->buffering = plcf->upstream.buffering;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_@name_copy_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = NULL;
    u->input_filter = NULL;
    u->input_filter_ctx = NULL;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_@name_create_key(ngx_http_request_t *r)
{
    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_@name_create_request(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_@name_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_@name_process_header(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_@name_input_filter_init(void *data)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_@name_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    return NGX_OK;
}


static void
ngx_http_@name_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http @name request");

    return;
}


static void
ngx_http_@name_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http @name request");

    return;
}


@preConfDefine


@postConfDefine


@createMainDefine


@initMainDefine


@createSrvDefine


@mergeSrvDefine


static void *
ngx_http_@name_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_@name_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_@name_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     */

    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

#if (NGX_HTTP_CACHE)
    conf->upstream.cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
    conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_lock = NGX_CONF_UNSET;
    conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
#endif

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

    /* "@name_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    ngx_str_set(&conf->upstream.module, "@name");

    return conf;
}


static char *
ngx_http_@name_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_@name_loc_conf_t *prev = parent;
    ngx_http_@name_loc_conf_t *conf = child;

    u_char                     *p;
    size_t                      size;
    ngx_hash_init_t             hash;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_@name_redirect_t  *pr;
    ngx_http_script_compile_t   sc;

    if (conf->upstream.store != 0) {
        ngx_conf_merge_value(conf->upstream.store,
                              prev->upstream.store, 0);

        if (conf->upstream.store_lengths == NULL) {
            conf->upstream.store_lengths = prev->upstream.store_lengths;
            conf->upstream.store_values = prev->upstream.store_values;
        }
    }

    ngx_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    ngx_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"@name_buffers\"");
        return NGX_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"@name_busy_buffers_size\" must be equal or bigger than "
             "maximum of the value of \"@name_buffer_size\" and "
             "one of the \"@name_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"@name_busy_buffers_size\" must be less than "
             "the size of all \"@name_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"@name_temp_file_write_size\" must be equal or bigger than "
             "maximum of the value of \"@name_buffer_size\" and "
             "one of the \"@name_buffers\"");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"@name_max_temp_file_size\" must be equal to zero to disable "
             "the temporary files usage or must be equal or bigger than "
             "maximum of the value of \"@name_buffer_size\" and "
             "one of the \"@name_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              NGX_CONF_BITMASK_SET);


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              &ngx_http_@name_temp_path)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }


#if (NGX_HTTP_CACHE)

    ngx_conf_merge_ptr_value(conf->upstream.cache,
                              prev->upstream.cache, NULL);

    if (conf->upstream.cache && conf->upstream.cache->data == NULL) {
        ngx_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"@name_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
                                         |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
        conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    if (conf->upstream.no_cache && conf->upstream.cache_bypass == NULL) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
             "\"@name_no_cache\" functionality has been changed in 0.8.46, "
             "now it should be used together with \"@name_cache_bypass\"");
    }

    ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

    ngx_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

#endif

    if (conf->method.len == 0) {
        conf->method = prev->method;

    } else {
        conf->method.data[conf->method.len] = ' ';
        conf->method.len++;
    }

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, ngx_http_@name_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->@name_lengths == NULL) {
        conf->@name_lengths = prev->@name_lengths;
        conf->@name_values = prev->@name_values;
    }

    if (conf->upstream.upstream || conf->@name_lengths) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf->handler == NULL && clcf->lmt_excpt) {
            clcf->handler = ngx_http_@name_handler;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_@name_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_@name_loc_conf_t *plcf = conf;

    ngx_str_t                  *value, *url;
    ngx_url_t                   u;
    ngx_uint_t                  n;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_script_compile_t   sc;

    if (plcf->upstream.upstream || plcf->@name_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_@name_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;

    url = &value[1];

    n = ngx_http_script_variables_count(url);

    if (n) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &plcf->@name_lengths;
        sc.values = &plcf->@name_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    flcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (flcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_@name_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_@name_loc_conf_t *plcf = conf;

    ngx_str_t                  *value;
    ngx_http_script_compile_t   sc;

    if (plcf->upstream.store != NGX_CONF_UNSET
        || plcf->upstream.store_lengths)
    {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        plcf->upstream.store = 0;
        return NGX_CONF_OK;
    }

#if (NGX_HTTP_CACHE)

    if (plcf->upstream.cache != NGX_CONF_UNSET_PTR
        && plcf->upstream.cache != NULL)
    {
        return "is incompatible with \"@name_cache\"";
    }

#endif

    if (ngx_strcmp(value[1].data, "on") == 0) {
        plcf->upstream.store = 1;
        return NGX_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &plcf->upstream.store_lengths;
    sc.values = &plcf->upstream.store_values;
    sc.variables = ngx_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#if (NGX_HTTP_CACHE)

static char *
ngx_http_@name_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_@name_loc_conf_t *plcf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    if (plcf->upstream.cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        plcf->upstream.cache = NULL;
        return NGX_CONF_OK;
    }

    if (plcf->upstream.store > 0 || plcf->upstream.store_lengths) {
        return "is incompatible with \"@name_store\"";
    }

    plcf->upstream.cache = ngx_shared_memory_add(cf, &value[1], 0,
                                                 &ngx_http_@name_module);
    if (plcf->upstream.cache == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_@name_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_@name_loc_conf_t *plcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (plcf->cache_key.value.len) {
        return "is duplicate";
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &plcf->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#endif


static char *
ngx_http_@name_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"@name_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"@name#_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}


"""

ngx_preconf_declare_template = "static ngx_int_t ngx_http_@name_preconfiguration(ngx_conf_t *cf);"
ngx_postconf_declare_template = "static ngx_int_t ngx_http_@name_postconfiguration(ngx_conf_t *cf);"
ngx_create_main_declare_template = "static void *ngx_http_@name_create_main_conf(ngx_conf_t *cf);"
ngx_init_main_declare_template = "static char *ngx_http_@name_init_main_conf(ngx_conf_t *cf, void *conf);"
ngx_create_srv_declare_template = "static void *ngx_http_@name_create_srv_conf(ngx_conf_t *cf);"
ngx_merge_srv_declare_template = """
static char *ngx_http_@name_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);"""
ngx_create_loc_declare_template = "static void *ngx_http_@name_create_loc_conf(ngx_conf_t *cf);"
ngx_merge_loc_declare_template = """
static char *ngx_http_@name_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);"""

ngx_preconf_name = "ngx_http_@name_preconfiguration"
ngx_postconf_name = "ngx_http_@name_postconfiguration"
ngx_create_main_name = "ngx_http_@name_create_main_conf"
ngx_init_main_name = "ngx_http_@name_init_main_conf"
ngx_create_srv_name = "ngx_http_@name_create_srv_conf"
ngx_merge_srv_name = "ngx_http_@name_merge_srv_conf"
ngx_create_loc_name = "ngx_http_@name_create_loc_conf"
ngx_merge_loc_name = "ngx_http_@name_merge_loc_conf"


ngx_preconf_define_template = """
static ngx_int_t
ngx_http_@name_preconfiguration(ngx_conf_t *cf)
{
    return NGX_OK;
}
"""

ngx_postconf_define_template = """
static ngx_int_t
ngx_http_@name_postconfiguration(ngx_conf_t *cf)
{
    return NGX_OK;
}
"""

ngx_create_main_define_template = """
static void *
ngx_http_@name_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_@name_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_@name_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    return mcf;
}
"""

ngx_init_main_define_template = """
static char *
ngx_http_@name_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_core_main_conf_t *cmcf = conf;

    return NGX_CONF_OK;
}
"""

ngx_create_srv_define_template = """
static void *
ngx_http_@name_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_@name_srv_conf_t  *scf;

    scf = ngx_pcalloc(cf->pool, sizeof(ngx_http_@name_srv_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    return scf;
}
"""

ngx_merge_srv_define_template = """
static char *
ngx_http_@name_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_core_srv_conf_t *prev = parent;
    ngx_http_core_srv_conf_t *conf = child;

    return NGX_CONF_OK;
}
"""

ngx_create_loc_define_template = """
static void *
ngx_http_@name_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_@name_loc_conf_t  *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_@name_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    return lcf;
}
"""

ngx_merge_loc_define_template = """
static char *
ngx_http_@name_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_@name_loc_conf_t *prev = parent;
    ngx_http_@name_loc_conf_t *conf = child;

    return NGX_CONF_OK;
}
"""

ngx_module_name = {"filter" : "ngx_http_@name_filter_module.c",
                   "f" : "ngx_http_@name_filter_module.c",
                   "content_handler": "ngx_http_@name_module.c",
                   "c": "ngx_http_@name_module.c",
                   "upstream": "ngx_http_@name_module.c", 
                   "u": "ngx_http_@name_module.c"}

ngx_module_config = {"content_handler" : ngx_content_handler_config,
                     "c" : ngx_content_handler_config,
                     "filter": ngx_filter_module_config,
                     "f": ngx_filter_module_config,
                     "upstream" : ngx_content_handler_config,
                     "u" : ngx_content_handler_config}

ngx_module_template = {"content_handler" : ngx_content_handler_template,
                       "c" : ngx_content_handler_template,
                       "filter": ngx_filter_module_template,
                       "f": ngx_filter_module_template,
                       "upstream": ngx_upstream_template, 
                       "u": ngx_upstream_template}

def ngx_conf_set_pre_handler(d):
    d["preConfDeclare"] = ngx_preconf_declare_template
    d["preConfName"] = ngx_preconf_name
    d["preConfDefine"] = ngx_preconf_define_template

def ngx_conf_set_post_handler(d):
    d["postConfDeclare"] = ngx_postconf_declare_template
    d["postConfName"] = ngx_postconf_name
    d["postConfDefine"] = ngx_postconf_define_template

def ngx_conf_set_main_handler(d):
    d["createMainDeclare"] = ngx_create_main_declare_template
    d["createMainName"] = ngx_create_main_name
    d["createMainDefine"] = ngx_create_main_define_template
    d["initMainDeclare"] = ngx_init_main_declare_template
    d["initMainName"] = ngx_init_main_name
    d["initMainDefine"] = ngx_init_main_define_template

def ngx_conf_set_srv_handler(d):
    d["createSrvDeclare"] = ngx_create_srv_declare_template
    d["createSrvName"] = ngx_create_srv_name
    d["createSrvDefine"] = ngx_create_srv_define_template
    d["mergeSrvDeclare"] = ngx_merge_srv_declare_template
    d["mergeSrvName"] = ngx_merge_srv_name
    d["mergeSrvDefine"] = ngx_merge_srv_define_template

def ngx_conf_set_loc_handler(d):
    d["createLocDeclare"] = ngx_create_loc_declare_template
    d["createLocName"] = ngx_create_loc_name
    d["createLocDefine"] = ngx_create_loc_define_template
    d["mergeLocDeclare"] = ngx_merge_loc_declare_template
    d["mergeLocName"] = ngx_merge_loc_name
    d["mergeLocDefine"] = ngx_merge_loc_define_template

def ngx_conf_set_all_handler(d):
    ngx_conf_set_pre_handler(d)
    ngx_conf_set_post_handler(d)
    ngx_conf_set_main_handler(d)
    ngx_conf_set_srv_handler(d)
    ngx_conf_set_loc_handler(d)
    
ngx_module_conf_template = { "pre": ngx_conf_set_pre_handler,
    "post": ngx_conf_set_post_handler,
    "main": ngx_conf_set_main_handler,
    "srv": ngx_conf_set_srv_handler,
    "loc": ngx_conf_set_loc_handler,
    "all": ngx_conf_set_all_handler,}

class Ngx_scaffold_template(string.Template):
    delimiter = '@'
    idpattern = '[a-z]+'
    
def ngx_module_parse_args():
    parser = argparse.ArgumentParser(description='Nginx module scaffold.')
    parser.add_argument('--module_type', '-mt', dest="module_type",
                        help='module type (filter[f]/content_handler[c]/upstream[u])',
                        required=True)
    parser.add_argument('--module_name', '-mn', dest="module_name", help='module name', required=True)
    parser.add_argument('--module_path', '-mp', dest="module_path", help='module_path')
    parser.add_argument('--module_conf', '-mc', dest="module_conf",
                        help='module_conf(pre/post/main/srv/loc/all)', default="all")
    args = parser.parse_args()
    return args

def ngx_module_write_file(name, data, path):
    if path:
        name = path + '/' + name
    try:
        f = open (name, "w")
    except:
        print "open file(%s) failed" % name
        exit(1)
    try:
        f.write(data)
    except:
        f.close()
        print "write file(%s) failed" % name
        exit(1)
    f.close()

def ngx_module_get_data(conf_dict, format_dict, args):
    try:
        format_str = format_dict[args.module_type]
    except KeyError:
        print "please enter correct module type(filter/content_handler/upstream)"
        exit(1)
    s = Ngx_scaffold_template(format_str)
    data = s.safe_substitute(conf_dict)
    s2 = Ngx_scaffold_template(data)
    data = s2.substitute(name = args.module_name)
    clean = re.compile('\n{4,}')
    data = re.subn(clean, '\n\n\n', data)
    return data[0]

def ngx_combine_conf_dict(d, args):
    conf_list = string.split(args.module_conf, '|')
    for l in conf_list:
        try:
            ngx_module_conf_template[l](d)
        except KeyError:
            print "please enter correct module conf(pre/post/main/srv/loc/all)"
            exit(1)

def ngx_module_conf_init_dict(d):
    d["preConfDeclare"] = ""
    d["preConfName"] = "NULL"
    d["preConfDefine"] = ""
    d["postConfDeclare"] = ""
    d["postConfName"] = "NULL"
    d["postConfDefine"] = ""
    d["createMainDeclare"] = ""
    d["createMainName"] = "NULL"
    d["createMainDefine"] = ""
    d["initMainDeclare"] = ""
    d["initMainName"] = "NULL"
    d["initMainDefine"] = ""
    d["createSrvDeclare"] = ""
    d["createSrvName"] = "NULL"
    d["createSrvDefine"] = ""
    d["mergeSrvDeclare"] = ""
    d["mergeSrvName"] = "NULL"
    d["mergeSrvDefine"] = ""
    d["createLocDeclare"] = ""
    d["createLocName"] = "NULL"
    d["createLocDefine"] = ""
    d["mergeLocDeclare"] = ""
    d["mergeLocName"] = "NULL"
    d["mergeLocDefine"] = ""
   
def ngx_module_scaffold(args):
    d = {}
    ngx_module_conf_init_dict(d)
    ngx_combine_conf_dict(d, args);
    file_name = ngx_module_get_data(d, ngx_module_name, args)
    config = ngx_module_get_data(d, ngx_module_config, args)
    file_data = ngx_module_get_data(d, ngx_module_template, args)
    ngx_module_write_file(file_name, file_data, args.module_path)
    ngx_module_write_file("config", config, args.module_path)

    
if __name__ == "__main__":
    args = ngx_module_parse_args()
    ngx_module_scaffold(args)
    
