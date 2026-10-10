// Modify only JSON responses; other content continues unchanged.
try {
  const body = JSON.parse($response.body);
  const options = JSON.parse($argument || "{}");
  body.dae = {
    runtime: $environment["dae-runtime"],
    marker: options.marker || "dae-" + $environment["dae-runtime"],
  };
  $done({ body: JSON.stringify(body) });
} catch (error) {
  console.log("demo: response is not JSON:", String(error));
  $done({});
}
