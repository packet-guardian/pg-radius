# Packet Guardian Freeradius Rest Client

## Requirements

On Ubuntu, install `freeradius-rest`.

## Freeradius config

`sites-enabled/default`:

```
authorize {
    rest
    if (ok || updated) {
        update control {
            Auth-Type := Accept
        }
    }
}

authenticate {
    rest
}
```

`modules-enabled/rest`:

```
rest {
    tls {}

    connect_uri = "http://127.0.0.1:9000"

    authorize {
        uri = "${..connect_uri}/radius"
        method = 'post'
        body = 'json'
        tls = ${..tls}
        force_to = 'json'
    }

    authenticate {
        uri = "${..connect_uri}/radius"
        method = 'post'
        body = 'json'
        tls = ${..tls}
        force_to = 'json'
    }

    pool {
        start = ${thread[pool].start_servers}
        min = ${thread[pool].min_spare_servers}
        max = ${thread[pool].max_servers}
        spare = ${thread[pool].max_spare_servers}
        uses = 0
        retry_delay = 30
        lifetime = 0
        idle_timeout = 60
    }
}
```
