/**
library server

This package is registered when Lily is run by Apache through mod_lily. This
package provides Lily with information inside of Apache (such as POST), as well
as functions for sending data through the Apache server.
*/

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "util_script.h"

#include "lily_api_embed.h"
#include "lily_api_msgbuf.h"
#include "lily_api_value.h"

/** Begin autogen section. **/
#define ID_HtmlString(state) lily_cid_at(state, 0)

#define ID_Tainted(state) lily_cid_at(state, 1)

const char *lily_server_table[] = {
    "\02HtmlString\0Tainted\0"
    ,"N\02HtmlString\0"
    ,"m\0<new>\0(String):HtmlString"
    ,"1\0text\0String"
    ,"N\03Tainted\0"
    ,"m\0<new>\0[A](A):Tainted[A]"
    ,"m\0sanitize\0[A,B](Tainted[A],Function(A=>B)):B"
    ,"1\0value\0A"
    ,"F\0write\0(HtmlString)"
    ,"F\0write_literal\0(String)"
    ,"F\0write_unsafe\0(String)"
    ,"R\0env\0Hash[String, Tainted[String]]"
    ,"R\0get\0Hash[String, Tainted[String]]"
    ,"R\0http_method\0String"
    ,"R\0post\0Hash[String, Tainted[String]]"
    ,"Z"
};
#define HtmlString_OFFSET 1
#define Tainted_OFFSET 4
#define toplevel_OFFSET 8
void lily_server_HtmlString_new(lily_state *);
void lily_server_Tainted_new(lily_state *);
void lily_server_Tainted_sanitize(lily_state *);
void lily_server__write(lily_state *);
void lily_server__write_literal(lily_state *);
void lily_server__write_unsafe(lily_state *);
void lily_server_var_env(lily_state *);
void lily_server_var_get(lily_state *);
void lily_server_var_http_method(lily_state *);
void lily_server_var_post(lily_state *);
void *lily_server_loader(lily_state *s, int id)
{
    switch (id) {
        case HtmlString_OFFSET + 1: return lily_server_HtmlString_new;
        case Tainted_OFFSET + 1: return lily_server_Tainted_new;
        case Tainted_OFFSET + 2: return lily_server_Tainted_sanitize;
        case toplevel_OFFSET + 0: return lily_server__write;
        case toplevel_OFFSET + 1: return lily_server__write_literal;
        case toplevel_OFFSET + 2: return lily_server__write_unsafe;
        case toplevel_OFFSET + 3: lily_server_var_env(s); return NULL;
        case toplevel_OFFSET + 4: lily_server_var_get(s); return NULL;
        case toplevel_OFFSET + 5: lily_server_var_http_method(s); return NULL;
        case toplevel_OFFSET + 6: lily_server_var_post(s); return NULL;
        default: return NULL;
    }
}
/** End autogen section. **/

typedef struct {
    lily_hash_val *hash;
    lily_state *s;
} bind_table_data;

/**
native class HtmlString(value: String) {
    private var @text: String
}

This class provides a wrapper over a `String`. The constructor of this class
will replace any of `"&<>"` with the appropriate html entity. Thus, instances of
this class are guaranteed to be html-encoded. The caller is responsible for
not encoding the data themselves beforehand (or it will be double-encoded).
*/

void lily_server_HtmlString_new(lily_state *s)
{
    lily_container_val *con;
    lily_instance_super(s, &con, ID_HtmlString(s), 1);

    const char *text = lily_arg_string_raw(s, 0);
    lily_msgbuf *msgbuf = lily_get_clean_msgbuf(s);

    if (lily_mb_html_escape(msgbuf, text) == text)
        lily_nth_set(con, 0, lily_arg_value(s, 0));
    else
        lily_nth_set(con, 0, lily_box_string(s, lily_new_string(text)));

    lily_return_value(s, lily_take_value(s));
}

/**
native class Tainted[A](value: A) {
    private var @value: A
}

The `Tainted` type represents a wrapper over some data that is considered
unsafe. Data, once inside a `Tainted` value can only be retrieved using the
`Tainted.sanitize` function.
*/

void lily_server_Tainted_new(lily_state *s)
{
    lily_container_val *con;
    lily_instance_super(s, &con, ID_Tainted(s), 1);
    lily_nth_set(con, 0, lily_arg_value(s, 0));
    lily_return_value(s, lily_take_value(s));
}

/**
define Tainted.sanitize[B](fn: Function(A => B)): B

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
var http_method: String

This is the method that was used to make the request to the server.
Common values are "GET", and "POST".
*/
static void load_var_http_method(lily_state *s)
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
define write(text: HtmlString)

This writes the contents of the `String` hidden within `text`. No escape is
performed, because the `HtmlString` constructor is assumed to have done that
already.
*/
void lily_server__write(lily_state *s)
{
    const char *to_write = lily_value_string_raw(lily_arg_nth_get(s, 0, 0));
    ap_rputs(to_write, (request_rec *)lily_op_get_data(s));
}

/**
define write_literal(text: String)

Write `text` to the server **without** any entity escaping. This function
assumes that the value passed is a `String` literal. Internally, this does the
same work as `server.write_unsafe`. The use of this function is that it implies
a contract (only `String` literals are passed). In doing so calls to
`server.write_unsafe` (a necessary evil) stand out more.
*/
void lily_server__write_literal(lily_state *s)
{
    ap_rputs(lily_arg_string_raw(s, 0), (request_rec *)lily_op_get_data(s));
}

/**
define write_unsafe(text: String)

This writes `text` to the server **without** any entity escaping. This
function exists for cases when `text` is already escaped, or when `text` could
never reasonably contain html entities.
*/
void lily_server__write_unsafe(lily_state *s)
{
    ap_rputs(lily_arg_string_raw(s, 0), (request_rec *)lily_op_get_data(s));
}
