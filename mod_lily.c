/*  mod_lily.c
    This is an apache binding for the Lily language. */
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "util_script.h"

#include "lily_api_embed.h"
#include "lily_api_msgbuf.h"
#include "lily_api_value.h"

#include "extras_server.h"

typedef struct {
    int show_traceback;
} lily_config_rec;

module AP_MODULE_DECLARE_DATA lily_module;

typedef struct {
    lily_hash_val *hash;
    lily_state *s;
} bind_table_data;

/**
embedded server

This package is registered when Lily is run by Apache through mod_lily. This
package provides Lily with information inside of Apache (such as POST), as well
as functions for sending data through the Apache server.
*/

/**
native Tainted[A]
    private var @value: A

The `Tainted` type represents a wrapper over some data that is considered
unsafe. Data, once inside a `Tainted` value can only be retrieved using the
`Tainted.sanitize` function.
*/

/**
constructor Tainted[A](value: A): Tainted[A]
*/
void lily_server_Tainted_new(lily_state *s)
{
    lily_container_val *con;
    lily_instance_super(s, &con, ID_Tainted(s), 1);
    lily_nth_set(con, 0, lily_arg_value(s, 0));
    lily_return_value(s, lily_take_value(s));
}

/**
method Tainted.sanitize[A, B](self: Tainted[A], fn: Function(A => B)): B

This calls `fn` with the value contained within `self`. `fn` is assumed to be a
function that can sanitize the data within `self`.
*/
void lily_server_Tainted_sanitize(lily_state *s)
{
    lily_container_val *instance_val = lily_arg_container(s, 0);

    lily_push_value(s, lily_nth_get(instance_val, 0));

    lily_call_simple(s, lily_arg_function(s, 1), 1);

    lily_return_value(s, lily_result_value(s));
}

static void add_hash_entry(bind_table_data *table_data, lily_string_val *key,
        lily_string_val *record)
{
    lily_state *s = table_data->s;
    lily_container_val *rec = lily_new_instance(ID_Tainted(s), 1);
    lily_nth_set(rec, 0, lily_box_string(s, record));

    lily_hash_insert_str(table_data->hash, key, lily_box_instance(s, rec));
}

static int bind_table_entry(void *data, const char *key, const char *value)
{
    /* Don't allow anything to become a string that has invalid utf-8, because
       Lily's string type assumes valid utf-8. */
    if (lily_is_valid_utf8(key) == 0 ||
        lily_is_valid_utf8(value) == 0)
        return TRUE;

    bind_table_data *table_data = (bind_table_data *)data;

    lily_string_val *string_key = lily_new_string(key);
    lily_string_val *record = lily_new_string(value);

    add_hash_entry(table_data, string_key, record);
    return TRUE;
}

static void bind_table_as(lily_state *s, apr_table_t *table, char *name)
{
    bind_table_data table_data;
    table_data.hash = lily_new_hash_strtable();
    table_data.s = s;

    apr_table_do(bind_table_entry, &table_data, table, NULL);
    lily_push_hash(s, table_data.hash);
}

/**
var env: Hash[String, Tainted[String]]

This contains key+value pairs containing the current environment of the server.
*/
static void *load_var_env(lily_state *s)
{
    request_rec *r = (request_rec *)lily_op_get_data(s);
    ap_add_cgi_vars(r);
    ap_add_common_vars(r);

    bind_table_as(s, r->subprocess_env, "env");
}

/**
var get: Hash[String, Tainted[String]]

This contains key+value pairs that were sent to the server as GET variables.
Any pair that has a key or a value that is not valid utf-8 will not be present.
*/
static void load_var_get(lily_state *s)
{
    apr_table_t *http_get_args;
    ap_args_to_table((request_rec *)lily_op_get_data(s), &http_get_args);

    bind_table_as(s, http_get_args, "get");
}

/**
var httpmethod: String

This is the method that was used to make the request to the server.
Common values are "GET", and "POST".
*/
static void load_var_httpmethod(lily_state *s)
{
    request_rec *r = (request_rec *)lily_op_get_data(s);

    lily_push_string(s, lily_new_string(r->method));
}

/**
var post: Hash[String, Tainted[String]]

This contains key+value pairs that were sent to the server as POST variables.
Any pair that has a key or a value that is not valid utf-8 will not be present.
*/
static void load_var_post(lily_state *s)
{
    request_rec *r = (request_rec *)lily_op_get_data(s);
    apr_pool_t *pool;

    apr_pool_create(&pool, r->pool);

    apr_array_header_t *pairs;
    apr_off_t len;
    apr_size_t size;
    char *buffer;

    bind_table_data table_data;
    table_data.hash = lily_new_hash_strtable();
    table_data.s = s;

    /* Credit: I found out how to use this by reading httpd 2.4's mod_lua
       (specifically req_parsebody of lua_request.c). */
    int res = ap_parse_form_data(r, NULL, &pairs, -1, 1024 * 8);
    if (res == OK) {
        while (pairs && !apr_is_empty_array(pairs)) {
            ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
            if (lily_is_valid_utf8(pair->name) == 0)
                continue;

            apr_brigade_length(pair->value, 1, &len);
            size = (apr_size_t) len;
            buffer = apr_palloc(pool, size + 1);

            if (lily_is_valid_utf8(buffer) == 0)
                continue;

            apr_brigade_flatten(pair->value, buffer, &size);
            buffer[len] = 0;

            lily_string_val *key = lily_new_string(pair->name);
            /* Give the buffer to the value to save memory. */
            lily_string_val *record = lily_new_string(buffer);

            add_hash_entry(&table_data, key, record);
        }
    }

    apr_pool_clear(pool);
    lily_push_hash(s, table_data.hash);
}

/**
define escape(text: String): String

This checks `text` for having `"&"`, `"<"`, or `">"`. If any are found, then a
new String is created where those html entities are replaced (`"&"` becomes
`"&amp;"`, `"<"` becomes `"&lt;"`, `">"` becomes `"&gt;"`). Otherwise, `text` is
returned unchanged.
*/
void lily_server_escape(lily_state *s)
{
    lily_value *v = lily_arg_value(s, 0);
    const char *raw = lily_value_string_raw(v);
    lily_msgbuf *msgbuf = lily_get_msgbuf(s);

    if (lily_mb_html_escape(msgbuf, raw) == raw)
        lily_return_value(s, v);
    else
        lily_return_string(s, lily_new_string(lily_mb_get(msgbuf)));
}

/**
define write(text: String)

This escapes, then writes `text` to the server. It's a shorthand for
`server.write_raw(server.escape(text))`.
*/
void lily_server_write(lily_state *s)
{
    lily_msgbuf *msgbuf = lily_get_msgbuf(s);
    const char *value = lily_mb_html_escape(msgbuf, lily_arg_string_raw(s, 0));

    ap_rputs(value, (request_rec *)lily_op_get_data(s));
}

/**
define write_literal(text: String)

This writes `text` directly to the server. If `text` is not a `String` literal,
then `ValueError` is raised. No escaping is performed.
*/
void lily_server_write_literal(lily_state *s)
{
    lily_value *write_reg = lily_arg_value(s, 0);

    if (lily_value_is_derefable(write_reg) == 0)
        lily_ValueError(s, "The string passed must be a literal.");

    char *value = lily_arg_string_raw(s, 0);

    ap_rputs(value, (request_rec *)lily_op_get_data(s));
}

/**
define write_raw(text: String)

This writes `text` directly to the server without performing any HTML character
escaping. Use this only if you are certain that there is no possibility of HTML
injection.
*/
void lily_server_write_raw(lily_state *s)
{
    char *value = lily_arg_string_raw(s, 0);

    ap_rputs(value, (request_rec *)lily_op_get_data(s));
}

#include "dyna_server.h"

static int lily_handler(request_rec *r)
{
    if (r->handler == NULL || strcmp(r->handler, "lily"))
        return DECLINED;

    r->content_type = "text/html";

    lily_config_rec *conf = (lily_config_rec *)ap_get_module_config(
            r->per_dir_config, &lily_module);

    lily_state *state = lily_new_state();
    lily_op_data(state, r);
    lily_op_render_func(state, (lily_render_func) ap_rputs);
    register_server(state);

    int result = lily_render_file(state, r->filename);
    lily_msgbuf *msgbuf = lily_get_msgbuf(state);

    if (result == 0 && conf->show_traceback)
        ap_rputs(lily_mb_html_escape(msgbuf, lily_get_error(state)), r);

    lily_free_state(state);

    return OK;
}

static const char *cmd_lilytraceback(cmd_parms *cmd, void *p, int flag)
{
    lily_config_rec *conf = (lily_config_rec *)p;
    conf->show_traceback = flag;

    return NULL;
}

static void *perdir_create(apr_pool_t *p, char *dummy)
{
    lily_config_rec *conf = apr_pcalloc(p, sizeof(lily_config_rec));

    conf->show_traceback = 0;
    return conf;
}

static void *perdir_merge(apr_pool_t *pool, void *a, void *b)
{
    lily_config_rec *add = (lily_config_rec *)b;
    lily_config_rec *conf = apr_palloc(pool, sizeof(lily_config_rec));

    conf->show_traceback = add->show_traceback;

    return conf;
}

static const command_rec command_table[] = {
    AP_INIT_FLAG("LilyTraceback", cmd_lilytraceback, NULL, OR_FILEINFO,
            "If On, show interpreter exception traceback. Default: Off."),
    {NULL}
};

static void lily_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(lily_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA lily_module = {
    STANDARD20_MODULE_STUFF,
    perdir_create,         /* create per-dir    config structures */
    perdir_merge,          /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    command_table,         /* table of config file commands       */
    lily_register_hooks    /* register hooks                      */
};
