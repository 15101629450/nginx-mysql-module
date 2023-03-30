
#ifndef __MYSQL_MODULE_H__
#define __MYSQL_MODULE_H__

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <mysql_pack.h>

#define MYSQL_HEAD "mysql://"
#define MYSQL_HEAD_SIZE 8


typedef struct {
    ngx_url_t host;
    ngx_str_t user;
    ngx_str_t pass;
    ngx_str_t db;
    ngx_http_upstream_conf_t upstream;
    size_t buffer_size;
} ngx_mysql_conf_t;

typedef struct {
    mysql_pack pack;
    ngx_str_t sql;
    int stage;
} ngx_mysql_ctx_t;

typedef enum {
    MYSQL_READ_SERVER,
    MYSQL_READ_LOGIN,
    MYSQL_READ_SELECT,
} mysql_status_t;

ngx_int_t ngx_mysql_subrequest(ngx_http_request_t *r,
                               ngx_str_t location,
                               ngx_str_t sql,
                               ngx_http_post_subrequest_pt handler);

#endif 

