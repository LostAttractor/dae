{
  lib,
  # Matches the Makefile requirement of Go 1.27.2+.
  buildGo127Module,
  fetchPnpmDeps,
  pnpmConfigHook,
  pnpm_12,
  nodejs_22,
  llvmPackages_latest,
  installShellFiles,
  writeText,
  version,
  # Surge JavaScript backend: nodejs, which runs `node` from PATH, or quickjs.
  surgeRuntime ? "nodejs",
  # plugins.cfg content; null selects plugins.cfg.example.
  plugins ? null,
  # Source trees of the external plugin modules named in `plugins`.
  pluginModules ? [ ],
  # Executables that plugins look up in PATH at runtime, such as ffmpeg.
  runtimeInputs ? [ ],
  # Depends on `pluginModules`.
  vendorHash ? "sha256-ip2TlBamahK/YV2ijG9/kqfeeuby+kr1GyLYuMvxXAg=",
}:

let
  # Named by their inputs and the Nixpkgs version, whose fetchers produce them:
  # unchanged dependencies are reused across commits, and changed ones are
  # refetched, so a stale hash fails on every machine.
  depsName =
    kind: inputs:
    "dae-${kind}-${
      builtins.substring 0 16 (builtins.hashString "sha256" (toString ([ lib.version ] ++ inputs)))
    }";
in
buildGo127Module (finalAttrs: {
  pname = "dae";
  inherit version;

  src = ./..;

  # bpf2go runs with -mod=mod, which needs the module proxy layout.
  proxyVendor = true;
  inherit vendorHash;

  pnpmDeps =
    (fetchPnpmDeps {
      inherit (finalAttrs) pname src;
      pnpm = pnpm_12;
      fetcherVersion = 5;
      hash = "sha256-M0zIwY5O4WmJPK/U8zuiGtewrcSBwYtlFi56ibCEqMI=";
    }).overrideAttrs
      (old: {
        name = depsName "pnpm-deps" [
          old.passthru.fetcherVersion
          pnpm_12.version
          (builtins.hashFile "sha256" "${finalAttrs.src}/pnpm-lock.yaml")
        ];
      });

  nativeBuildInputs = [
    pnpmConfigHook
    pnpm_12
    nodejs_22
    installShellFiles
  ];

  overrideModAttrs = {
    name = depsName "go-modules" (
      map (builtins.hashFile "sha256") (
        [
          "${finalAttrs.src}/go.mod"
          "${finalAttrs.src}/go.sum"
        ]
        ++ lib.concatMap (
          m: [ "${m}/go.mod" ] ++ lib.optional (builtins.pathExists "${m}/go.sum") "${m}/go.sum"
        ) pluginModules
      )
    );
    # The Go module fetcher shares nativeBuildInputs but has no pnpmDeps.
    dontPnpmConfigure = true;
  };

  # Shared with the Go module fetcher; external plugins join a Go workspace.
  preBuild =
    lib.optionalString (plugins != null) ''
      cp ${writeText "plugins.cfg" plugins} plugins.cfg
    ''
    + lib.optionalString (pluginModules != [ ]) ''
      go work init . ${lib.escapeShellArgs pluginModules}
      go work edit -replace=github.com/daeuniverse/dae@v0.0.0=.
    '';

  # The Makefile selects cgo for the Surge runtime.
  buildPhase = ''
    runHook preBuild
    env -u CGO_ENABLED make \
      CLANG=${llvmPackages_latest.clang-unwrapped}/bin/clang \
      STRIP=${llvmPackages_latest.llvm}/bin/llvm-strip \
      SURGE_RUNTIME=${surgeRuntime} \
      VERSION=${finalAttrs.version}
    runHook postBuild
  '';

  # Tests need network access and root privileges.
  doCheck = false;

  installPhase = ''
    runHook preInstall
    install -Dm755 dae -t $out/bin
    install -Dm444 install/dae.service -t $out/lib/systemd/system
    substituteInPlace $out/lib/systemd/system/dae.service \
      --replace-fail /usr/bin/dae $out/bin/dae
    installShellCompletion install/shell-completion/dae.{bash,fish,zsh}
    runHook postInstall
  '';

  # The NixOS module adds these to the service PATH; Surge's nodejs backend runs `node`.
  passthru.runtimeInputs = lib.optional (surgeRuntime == "nodejs") nodejs_22 ++ runtimeInputs;

  meta = {
    description = "Linux high-performance transparent proxy solution based on eBPF";
    homepage = "https://github.com/LostAttractor/dae";
    license = lib.licenses.agpl3Only;
    platforms = lib.platforms.linux;
    mainProgram = "dae";
  };
})
