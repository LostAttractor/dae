// Modify only JSON responses; other content continues unchanged.
try {
  const body = JSON.parse($response.body);
  const options = JSON.parse($argument || "{}");
  body.dae = {
    runtime: "quickjs",
    marker: options.marker || "dae-quickjs",
  };
  $done({ body: JSON.stringify(body) });
} catch (error) {
  console.log("demo: response is not JSON:", String(error));
  $done({});
}
