lily-apache
===========

Lily server protocol: [Version 1.0](https://github.com/FascinatedBox/lily-server-protocol)

This package provides a bridge between Lily and the Apache web server. You'll
need to `make install` Lily so that Lily (the shared library) is available to
link against. The scripts that are executed by mod_lily will start in template
mode (code between `<?lily ... ?>` tags). However, any imports they perform are
done in code-only mode. Code-only files will **not** be served by this module.

This implementation provides a package called `server` for executed scripts to
import.

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
server.write_literal("Hello from mod_lily!")
?>
</body>
</html>
```

# Configuration

This implementation reads the configuration described in the server protocol
from Apache's configuration file. Example usage:

```
<Directory "/var/www/cgi-bin">
    SetHandler lily
    LilyTraceback On
</Directory>
```
