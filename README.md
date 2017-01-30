lily-apache
===========

This package provides a bridge between Lily and the Apache web server. You'll
need to `make install` Lily so that Lily (the shared library) is available to
link against. The scripts that are executed by mod_lily will start in template
mode (code between `<?lily ... ?>` tags). However, any imports they perform are
done in code-only mode. Code-only files will **not** be served by this module.

# Setup

Here's a configuration to get you started.

```
# Near the module section:
LoadModule    lily_module    /usr/lib64/httpd/modules/mod_lily.so

# After cgi-bin...
<Directory "/var/www/cgi-bin">
    SetHandler lily
</Directory>
```

Here's a test script, to make sure it works:

```
<?lily
import server
?>
<html>
<body>
<?lily
server.write("Hello from mod_lily!")
?>
</body>
</html>
```

# Configuration

The following configuration directives are accepted by `mod_lily`.

* __LilyTraceback__: If **On**, show error traceback. Default: **Off**.

# server

This package is registered when Lily is run by Apache through mod_lily. This
package provides Lily with information inside of Apache (such as POST), as well
as functions for sending data through the Apache server.

## toplevel

### var env: `Hash[String, Tainted[String]]`

This contains key+value pairs containing the current environment of the server.

### var get: `Hash[String, Tainted[String]]`

This contains key+value pairs that were sent to the server as GET variables.

### var httpmethod: `String`

This is the method that was used to make the request to the server.

### var post: `Hash[String, Tainted[String]]`

This contains key+value pairs that were sent to the server as POST variables.

### define write`(text: HtmlString)`

This writes the contents of the `String` hidden within `text`. No escape is
performed, because the `HtmlString` constructor is assumed to have done that
already. */
void lily_server_write(lily_state *s)
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

### define write_literal`(text: String)`

Write `text` to the server **without** any entity escaping. This function
assumes that the value passed is a `String` literal. Internally, this does the
same work as `server.write_unsafe`. The use of this function is that it implies
a contract (only `String` literals are passed). In doing so calls to
`server.write_unsafe` (a necessary evil) stand out more.

### define write_unsafe`(text: String)`

This writes `text` to the server **without** any entity escaping. This
function exists for cases when `text` is already escaped, or when `text` could
never reasonably contain html entities.

## class HtmlString

```
class HtmlString {
    private var @text: String
}
```

This class provides a wrapper over a `String`. The constructor of this class
will replace any of `"&<>"` with the appropriate html entity. Thus, instances of
this class are guaranteed to be html-encoded. The caller is responsible for
not encoding the data themselves beforehand (or it will be double-encoded).

### constructor HtmlString`(value: String): HtmlString`



## class Tainted

```
class Tainted[A] {
    private var @value: A
}
```

The `Tainted` type represents a wrapper over some data that is considered
unsafe. Data, once inside a `Tainted` value can only be retrieved using the
`Tainted.sanitize` function.

### constructor Tainted`[A](value: A): Tainted[A]`



### method Tainted.sanitize`[A, B](self: Tainted[A], fn: Function(A => B)): B`

This calls `fn` with the value contained within `self`. `fn` is assumed to be a
function that can sanitize the data within `self`.
