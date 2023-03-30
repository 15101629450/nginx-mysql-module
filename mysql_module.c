
#include <mysql_module.h>

void *ngx_mysql_conf_create(ngx_conf_t *cf);
char *ngx_mysql_conf_init(ngx_conf_t *cf, void *parent, void *child);
char *ngx_mysql_command(ngx_conf_t *cf, ngx_command_t *cmd, void *p);
static ngx_command_t  ngx_mysql_commands[] = {

        { ngx_string("mysql"),
          NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
          ngx_mysql_command,
          NGX_HTTP_LOC_CONF_OFFSET,
          0,
          NULL },
        { ngx_string("mysql_buffer_size"),
          NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_size_slot,
          NGX_HTTP_LOC_CONF_OFFSET,
          offsetof(ngx_mysql_conf_t, upstream.buffer_size),
          NULL },
	ngx_null_command
};

static ngx_http_module_t  ngx_mysql_module_ctx = {
	NULL,          /* preconfiguration */
	NULL,                                  /* postconfiguration */
	NULL,       /* create main configuration */
	NULL,                                  /* init main configuration */
	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */
	ngx_mysql_conf_create,        /* create location configuration */
	ngx_mysql_conf_init          /* merge location configuration */
};

ngx_module_t mysql_module = {
	NGX_MODULE_V1,
	&ngx_mysql_module_ctx,            /* module context */
	ngx_mysql_commands,               /* module directives */
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

ngx_int_t ngx_mysql_create_request(ngx_http_request_t *r)
{
    return NGX_OK;
}

ngx_int_t ngx_mysql_stage_request(ngx_http_request_t *r, void *buffer, size_t buffer_size)
{
	ngx_mysql_conf_t *conf = ngx_http_get_module_loc_conf(r, mysql_module);
	ngx_mysql_ctx_t *ctx = ngx_http_get_module_ctx(r, mysql_module);
    r->upstream->buffer.last = r->upstream->buffer.pos;
    ctx->stage++;

    int ret = mysql_pack_server_read(&ctx->pack, buffer, buffer_size);
    if (ret != MYSQL_OK) {
        return NGX_HTTP_NO_CONTENT;
    }

    u_char *temp = ngx_palloc(r->pool, MYSQL_MAX_BUFFER_SIZE);
    size_t size = mysql_pack_login(conf->user.data, conf->user.len,
                                conf->pass.data, conf->pass.len,
                                conf->db.data, conf->db.len,
                                ctx->pack.capabilities,
                                0,
                                ctx->pack.scramble,
                                temp);
    if (size == 0) {
        return NGX_HTTP_NO_CONTENT;
    }

    size += mysql_pack_select(ctx->sql.data, ctx->sql.len,&temp[size]);
    r->upstream->peer.connection->send(r->upstream->peer.connection, temp, size);
    return NGX_AGAIN;
}

ngx_int_t ngx_mysql_process_error(ngx_http_request_t *r)
{
    r->upstream->buffer.last = r->upstream->buffer.pos;
    return NGX_HTTP_NO_CONTENT;
}

ngx_int_t ngx_mysql_process_header(ngx_http_request_t *r)
{
    ngx_mysql_conf_t *conf = ngx_http_get_module_loc_conf(r, mysql_module);
    ngx_mysql_ctx_t *ctx = ngx_http_get_module_ctx(r, mysql_module);
    u_char *buffer = r->upstream->buffer.pos;
	size_t size = r->upstream->buffer.last - r->upstream->buffer.pos;
    fprintf(stdout, "[mysql][READ][%zd]\n", size);
    if (size >= conf->upstream.buffer_size) {
        return ngx_mysql_process_error(r);
    }

	if (!ctx->stage) {
        return ngx_mysql_stage_request(r, buffer, size);
	}

    int ret = mysql_pack_result_read(&ctx->pack, buffer, size);
    if (ret != MYSQL_OK) {
//        fprintf(stdout, "[mysql][mysql_pack_result_read][%d]\n", ret);
//        if (ret == MYSQL_IO_WAIT) {
//            return NGX_AGAIN;
//        }
//
//        return ngx_mysql_process_error(r);
        return NGX_AGAIN;

    }

    ret = mysql_pack_loop_read(&ctx->pack, NULL, NULL, NULL);
    if (ret != MYSQL_OK) {
//        fprintf(stdout, "[mysql][mysql_pack_loop][%d]\n", ret);
//        if (ret == MYSQL_IO_WAIT) {
//            return NGX_AGAIN;
//        }
//
//        return ngx_mysql_process_error(r);
        return NGX_AGAIN;

    }

    fprintf(stdout, "[mysql][END][%zd]\n", size);
    return NGX_OK;
}

void ngx_mysql_abort_request(ngx_http_request_t *r)
{
}

void ngx_mysql_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
}

ngx_int_t ngx_mysql_input_filter_init(void *data)
{
	return NGX_OK;
}

ngx_int_t ngx_mysql_input_filter(void *data, ssize_t size)
{
	return NGX_OK;
}

ngx_int_t ngx_mysql_upstream(ngx_http_request_t *r)
{
	if (ngx_http_upstream_create(r) != NGX_OK) {
		return NGX_HTTP_NO_CONTENT;
	}

	ngx_mysql_conf_t *conf = ngx_http_get_module_loc_conf(r, mysql_module);
	ngx_http_upstream_t *u = r->upstream;

	u->output.tag = (ngx_buf_tag_t)&mysql_module;
	u->conf = &conf->upstream;
	u->create_request = ngx_mysql_create_request;
	u->process_header = ngx_mysql_process_header;
    u->abort_request = ngx_mysql_abort_request;
    u->finalize_request = ngx_mysql_finalize_request;
	u->input_filter_init = ngx_mysql_input_filter_init;
	u->input_filter = ngx_mysql_input_filter;
	u->input_filter_ctx = r;
	u->input_filter = NULL;
	r->main->count++;

	ngx_http_upstream_init(r);
	return NGX_DONE;
}

ngx_int_t ngx_mysql_handler(ngx_http_request_t *r)
{
    if (!r->args.len || !r->args.data) {
        return NGX_HTTP_NO_CONTENT;
    }

    ngx_mysql_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(ngx_mysql_ctx_t));
    ctx->sql = r->args;
	ngx_http_set_ctx(r, ctx, mysql_module);
	return ngx_mysql_upstream(r);
}

void *ngx_mysql_conf_create(ngx_conf_t *cf)
{
	ngx_mysql_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_mysql_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
	conf->upstream.cyclic_temp_file = 0;
	conf->upstream.buffering = 0;
	conf->upstream.ignore_client_abort = 1;
	conf->upstream.send_lowat = 0;
	conf->upstream.bufs.num = 0;
	conf->upstream.busy_buffers_size = 0;
	conf->upstream.max_temp_file_size = 0;
	conf->upstream.temp_file_write_size = 0;
	conf->upstream.intercept_errors = 1;
	conf->upstream.intercept_404 = 1;
	conf->upstream.pass_request_headers = 0;
	conf->upstream.pass_request_body = 0;
	return conf;
}

char *ngx_mysql_conf_init(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_mysql_conf_t *prev = parent;
	ngx_mysql_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout,
                              1000 * 60);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout,
                              1000 * 60);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout,
                              1000 * 60);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              1024 * 1024);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                                 prev->upstream.next_upstream,
                                 (NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_ERROR | NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

//    fprintf(stdout, "[mysql][buffer_size][%zd]\n", conf->upstream.buffer_size);
    return NGX_CONF_OK;
}

int ngx_mysql_uri_parse(ngx_str_t mysql_uri, ngx_mysql_conf_t *conf)
{
	if (!mysql_uri.len || !mysql_uri.data) {
		return NGX_ERROR;
	}

	char *pos = (char *)mysql_uri.data;
	if (strncmp(pos, MYSQL_HEAD, MYSQL_HEAD_SIZE) != 0) {
		return NGX_ERROR;
	}

	char *user = strtok(pos+MYSQL_HEAD_SIZE, "@");
	char *host = strtok(NULL, "@");
	if (!user || !host) {
		return NGX_ERROR;
	}

	strtok(host, "/");
	char *db = strtok(NULL, "/");
	if (!db) {
		return NGX_ERROR;
	}

	strtok(user, ":");
	char *pass = strtok(NULL, ":");

	strtok(host, ":");
	char *port = strtok(NULL, ":");

	conf->user.data = (u_char *)user;
	conf->user.len = strlen(user);
	if (pass) {
		conf->pass.data = (u_char *)pass;
		conf->pass.len = strlen(pass);
	}

	conf->host.url.data = (u_char *)host;
	conf->host.url.len = strlen(host);
	conf->host.no_resolve = 1;
	if (port) {
		conf->host.default_port = atoi(port);

	} else {
		conf->host.default_port = 3306;
	}

	conf->db.data = (u_char *)db;
	conf->db.len = strlen(db);
	if (!conf->db.len) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

int ngx_mysql_uri_init(ngx_str_t mysql_uri, ngx_mysql_conf_t *conf, ngx_conf_t *cf)
{
	if (ngx_mysql_uri_parse(mysql_uri, conf)) {
		return NGX_ERROR;
	}

	conf->upstream.upstream = ngx_http_upstream_add(cf, &conf->host, 0);
	if (conf->upstream.upstream == NULL) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

char *ngx_mysql_command(ngx_conf_t *cf, ngx_command_t *cmd, void *p)
{
	ngx_mysql_conf_t *conf = p;
	if (conf->upstream.upstream) {
		return "mysql is duplicate";
	}

	ngx_str_t mysql_uri = ((ngx_str_t *)cf->args->elts)[1];
	if (ngx_mysql_uri_init(mysql_uri, conf, cf)) {
		return NGX_CONF_ERROR;
	}

	fprintf(stdout, "[mysql][host][%.*s][%d]\n",  (int)conf->host.url.len,      conf->host.url.data, conf->host.default_port);
	fprintf(stdout, "[mysql][user][%.*s]\n",      (int)conf->user.len,          conf->user.data);
	fprintf(stdout, "[mysql][pass][%.*s]\n",      (int)conf->pass.len,          conf->pass.data);
	fprintf(stdout, "[mysql][db][%.*s]\n",        (int)conf->db.len,            conf->db.data);
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_mysql_handler;
	return NGX_CONF_OK;
}

ngx_int_t ngx_mysql_subrequest(ngx_http_request_t *r,
                               ngx_str_t location,
                               ngx_str_t sql,
                               ngx_http_post_subrequest_pt handler)
{
    ngx_http_request_t *sr = NULL;
    ngx_http_post_subrequest_t *ps = ngx_pcalloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    ps->handler = handler;
    if (ngx_http_subrequest(r,
                            &location,
                            &sql,
                            &sr,
                            ps,
                            NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK) {
        return NGX_ERROR;
    }

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    sr->header_only = 1;
    return NGX_AGAIN;
}

