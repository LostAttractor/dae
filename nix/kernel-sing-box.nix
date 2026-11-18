# The interoperability peer is an upstream release, independent of dae's dependencies.
{
  stdenv,
  fetchurl,
  autoPatchelfHook,
}:
let
  targets = {
    x86_64-linux = {
      arch = "amd64";
      sha256 = "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968";
    };
    aarch64-linux = {
      arch = "arm64";
      sha256 = "436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26";
    };
  };
  target = targets.${stdenv.hostPlatform.system};
in
stdenv.mkDerivation (final: {
  pname = "sing-box-kernel-test-peer";
  version = "1.14.4";
  src = fetchurl {
    url = "https://github.com/SagerNet/sing-box/releases/download/v${final.version}/sing-box-${final.version}-linux-${target.arch}.tar.gz";
    inherit (target) sha256;
  };
  nativeBuildInputs = [ autoPatchelfHook ];
  dontStrip = true;
  installPhase = "install -Dm755 sing-box $out/bin/sing-box";
})
