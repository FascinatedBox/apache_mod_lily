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

### define escape`(text: String): String`

This checks `text` for having `"&"`, `"<"`, or `">"`. If any are found, then a
new String is created where those html entities are replaced (`"&"` becomes
`"&amp;"`, `"<"` becomes `"&lt;"`, `">"` becomes `"&gt;"`).

### define write`(text: String)`

This escapes, then writes `text` to the server. It is equivalent to
`server.write_raw(server.escape(text))`, except faster because it skips building
an intermediate `String` value.

### define write_literal`(text: String)`

This writes `text` directly to the server. If `text` is not a `String` literal,
then `ValueError` is raised. No escaping is performed.

### define write_raw`(text: String)`

This writes `text` directly to the server without performing any HTML character
escaping. Use this only if you are certain that there is no possibility of HTML
injection.

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
