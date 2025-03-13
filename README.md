# Nginx Stream Module ngx_stream_minecraft_forward_module

`ngx_stream_minecraft_forward_module` module is an Nginx module that can sieve Minecraft Java game traffic.

## Features

- Sieve and replace client-provided server hostname.

> [!IMPORTANT]
> - This module relies on [stream module](https://nginx.org/en/docs/stream/ngx_stream_core_module.html).
> - Only suitable for Minecraft Java protocol since Netty rewrite.
> - This module uses C++11. Add `--with-ld-opt="-lstdc++"` whilst compiling Nginx.

## Directives

- Syntax: `minecraft_server_forward  off|on;` <br/>
  Default: `minecraft_server_forward  off;` <br/>
  Context: server <br/>

  Indicate a server block that proxies Minecraft Java tcp connections.

> [!CAUTION]
> Set to `on` only when upstream server is a Minecraft Java server, otherwise proxy won't function properly.

<hr/>

- Syntax: `minecraft_server_hostname  hostname.to.be.replaced  new.hostname;` <br/>
  Default: None <br/>
  Context: stream, server <br/>

  When a client starts logging process, replace client-provided server hostname with a new hostname before proxying to remote Minecraft server.

> [!TIP]
> Due to differences in Minecraft Java protocol specification, should there be a SRV record `_minecraft._tcp.a.domain.for.example.com` that points to `another.domain.for.example.com`, consider define two replacements:

```
minecraft_server_hostname  a.domain.for.example.com        new.domain.for.example.com;
minecraft_server_hostname  another.domain.for.example.com  new.domain.for.example.com;
```

<hr/>

- Syntax: `minecraft_server_hostname_hash_max_size  size;` <br/>
  Default: `minecraft_server_hostname_hash_max_size  512;` <br/>
  Context: stream, server <br/>

  Set the maximum size of hash tables used by `minecraft_server_hostname` directive.

<hr/>

- Syntax: `minecraft_server_hostname_hash_bucket_size  size;` <br/>
  Default: `minecraft_server_hostname_hash_bucket_size  64;` <br/>
  Context: stream, server <br/>

  Set the bucket size for hash tables used by `minecraft_server_hostname` directive.

<hr/>

- Syntax: `minecraft_server_hostname_disconnect_on_nomatch  off|on;` <br/>
  Default: `minecraft_server_hostname_disconnect_on_nomatch  off;` <br/>
  Context: stream, server <br/>

  Close connection if client-provided server hostname matches no replacement.

<hr/>

- Syntax: `minecraft_server_hostname_replace_on_ping  off|on;` <br/>
  Default: `minecraft_server_hostname_replace_on_ping  on;` <br/>
  Context: stream, server <br/>

  When a client starts pinging, replace client-provided server hostname with a new hostname before proxying to remote Minecraft server. This option is recommended pinging servers hidden behind third-party services (e.g. TCPShield.com) that impose inspection on pinging packets.
