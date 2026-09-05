// Surge-compatible HTTP request script, executed by dae's QuickJS runtime.
const options = JSON.parse($argument || "{}");
const headers = { ...$request.headers };
headers["X-Dae-Runtime"] = options.marker || "dae-quickjs";
$done({ headers });
