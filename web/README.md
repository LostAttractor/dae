# dae Web

The browser application uses dae's HTTP API. This directory builds independently
of the daemon and Go toolchain; it currently needs only Make and standard file
utilities.

```sh
make
```

`src/` contains the frontend source. The build replaces `dist/` with the public
bundle, including `index.html`. Set `DIST=/absolute/output/path` to choose another
build directory. Only deploy build output; development files stay outside it.

In the dae repository, `make web` writes the bundle to `build/web/` by default.
The daemon build copies that output into its embedding package. To update a
running installation independently, deploy the bundle and set `DAE_WEB_ROOT` to
its directory in the daemon's service environment.

The page is served at `http://ROUTER_IP:<api_port>/`. Use root-relative API paths
such as `/api/device`; `/api/`, `/ca.pem`, `/ca.cer` and `/ca.mobileconfig` belong
to the daemon. Assets can use subdirectories. Missing paths return `404`; the
server does not provide a single-page application routing fallback.

The API contract is documented in the dae repository at `docs/api/openapi.json`
and `docs/en/configuration/api-client.md`. Keep API requests in `src/api.js` and
presentation in the frontend; this directory does not import daemon code.
