#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "util_script.h"

#include "lily.h"

extern const char *lily_server_info_table[];
extern lily_call_entry_func lily_server_call_table[];

typedef struct {
    int show_traceback;
} lily_config_rec;

module AP_MODULE_DECLARE_DATA lily_module;

static int lily_handler(request_rec *r)
{
    if (r->handler == NULL || strcmp(r->handler, "lily"))
        return DECLINED;

    r->content_type = "text/html";

    lily_config_rec *conf = (lily_config_rec *)ap_get_module_config(
            r->per_dir_config, &lily_module);

    lily_config config;

    lily_config_init(&config);
    config.data = r;
    config.render_func = (lily_render_func)ap_rputs;

    lily_state *state = lily_new_state(&config);
    lily_module_register(state, "server", lily_server_info_table,
            lily_server_call_table);

    int result = lily_render_file(state, r->filename);
    lily_msgbuf *msgbuf = lily_msgbuf_get(state);

    if (result == 0 && conf->show_traceback)
        ap_rputs(lily_mb_html_escape(msgbuf, lily_error_message(state)), r);

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
