# geoip-api

**If you do not require an auto-updating database or prometheus metrics, you should check out [ffissore/geoip-rs](https://github.com/ffissore/geoip-rs), the inspiration for this project.**

geoip-api is a geoip service: it provides geographical information about the specified IP address. It supports both IPV4 and IPV6.

-   When called with the `ip` query param, it resolves the specified IP address. For example: https://localhost:3000/?ip=216.58.205.132

    If the provided IP address is invalid, it returns an error

-   By default, responses will be in english. An optional `lang` query param can be provided: if a translation is available, returned data will be in that language. Current list includes: `de`, `en`, `es`, `fr`, `ja`, `pt-BR`, `ru`, `zh-CH`. For example: https://localhost:3000/?ip=216.58.205.132&lang=ja

-   Instead of reading from a file, geoip-api will regularly check for updates to the maxminddb online. See the usage below, on how to configure this.

### Example response

Valid ip address:

```json
{
    "ip_address": "46.51.179.90",
    "latitude": 53.3331,
    "longitude": -6.2489,
    "postal_code": "D02",
    "continent_code": "EU",
    "continent_name": "Europe",
    "country_code": "IE",
    "country_name": "Ireland",
    "region_code": "L",
    "region_name": "Leinster",
    "province_code": "",
    "province_name": "",
    "city_name": "Dublin",
    "timezone": "Europe/Dublin"
}
```

Not found (private) ip address (will return an 400 error code):

```
  AddressNotFoundError: Address not found in database
```

### Speed

I was able to achieve 150k requests per second on my machine.

geoip-api does choose to hold the entire database in memory, rather than writing it to a file.
Since it must download the new database while still serving requests from the old one, please allow at least 512 MB of memory for this.

### Usage

Install geoip-api with

```bash
cargo install geoip-api
```

If you don't have `cargo`, install it with

```bash
curl https://sh.rustup.rs -sSf | sh
```

or [read the tutorial](https://doc.rust-lang.org/cargo/getting-started/installation.html) for additional instructions.

You can specify options via the command-line or environment variables,

```bash
USAGE:
    geoip-api [OPTIONS] --account-id <account-id> --license-key <license-key>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --account-id <account-id>             [env: GEOIP_API_ACCOUNT_ID=]
        --edition-id <edition-id>             [env: GEOIP_API_EDITION_ID=]  [default: GeoIP2-City]
        --license-key <license-key>           [env: GEOIP_API_LICENSE_KEY=]
    -l, --listen-addr <listen-addr>           [env: GEOIP_API_LISTEN_ADDR=]  [default: 127.0.0.1:3000]
        --update-minutes <update-minutes>     [env: GEOIP_API_UPDATE_MINUTES=]  [default: 30]
```

e.g.

```bash
 geoip-api =-account-id 123456 --license-key s3cretlicense --update-minutes 30
 # or
 export GEOIP_API_ACCOUNT_ID=123456
 export GEOIP_API_LICENSE_KEY=s3cretlicense
 geoip-api
```

### License

This project is licensed under the Apache License, Version 2.0
