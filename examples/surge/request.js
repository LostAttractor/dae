// Surge-compatible HTTP request script, executed by dae's selected runtime.
const options = JSON.parse($argument || "{}");
const headers = { ...$request.headers };
headers["X-Dae-Runtime"] = options.marker || "dae-" + $environment["dae-runtime"];
$done({ headers });
