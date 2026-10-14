// Generated from docs/api/openapi.json. Run npm run types:api to update.
export interface paths {
    "/api/certificate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read public CA identity */
        get: operations["getCertificate"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/clients": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List active client groups and MAC members
         * @description Management authorization required.
         */
        get: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Client groups */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ClientGroups"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/clients/{name}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                name: components["parameters"]["Name"];
            };
            cookie?: never;
        };
        /**
         * Get a client group
         * @description Management authorization required.
         */
        get: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    name: components["parameters"]["Name"];
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Client group */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ClientGroup"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/clients/{name}/impact": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                name: components["parameters"]["Name"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Preview membership for a specified MAC
         * @description Management authorization and X-Dae-API: 1 required. Read-only, 64 KiB request limit.
         */
        post: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    name: components["parameters"]["Name"];
                };
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["ClientImpactRequest"];
                };
            };
            responses: {
                /** @description Membership impact */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ClientImpact"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/clients/{name}/members/{mac}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Nonzero unicast Ethernet MAC. */
                mac: components["parameters"]["MAC"];
                name: components["parameters"]["Name"];
            };
            cookie?: never;
        };
        get?: never;
        /**
         * Join a group by MAC
         * @description Management authorization, X-Dae-API: 1 and an empty body required. Uses the runtime settings persistence and rollback path.
         */
        put: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    /** @description Nonzero unicast Ethernet MAC. */
                    mac: components["parameters"]["MAC"];
                    name: components["parameters"]["Name"];
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Updated group */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ClientGroup"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        post?: never;
        /**
         * Leave a group by MAC
         * @description Management authorization, X-Dae-API: 1 and an empty body required.
         */
        delete: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    /** @description Nonzero unicast Ethernet MAC. */
                    mac: components["parameters"]["MAC"];
                    name: components["parameters"]["Name"];
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Updated group */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ClientGroup"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/device": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read the direct LAN caller's device state (TCP only) */
        get: operations["getDevice"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/device/certificate-tests": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create a current-browser CA and transparent MITM challenge (direct LAN only)
         * @description Empty body. Does not change the device's MITM setting. GET trust_url and, when enabled, mitm_url from the browser with credentials omitted and redirects rejected. CA challenges share the API listener's TLS branch; virtual IP:443 targets are answered locally by the interception plugin without an upstream service. Both accept only the original page's Origin and return CertificateTestProof. A failed virtual-target request cannot distinguish bypass from unreachable traffic. These exact-origin diagnostics are the only cross-origin browser endpoints.
         */
        post: operations["startCertificateTest"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/device/certificate-tests/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read this device's challenge observations */
        get: operations["getCertificateTest"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/device/context": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get verified LAN connection and inheritable context */
        get: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Verified connection context; device is omitted for IP-only ingress without an Ethernet MAC */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["DeviceContext"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/device/diagnostics/explain": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Explain a new flow for the verified LAN connection
         * @description Read-only. Requires X-Dae-API: 1 and verified LAN ingress. Ethernet ingress requires a direct matching neighbor; IP ingress requires no MAC. Identity overrides are rejected. Request limit 64 KiB, evaluation budget five seconds. No DNS queries, connections or scripts are executed.
         */
        post: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["ExplainRequest"];
                };
            };
            responses: {
                /** @description Explanation and optional same-snapshot comparison */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ExplainResponse"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/device/mitm": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Set this device's HTTPS module override (TCP only) */
        put: operations["setMITM"];
        post?: never;
        /** Restore this device's HTTPS configuration (TCP only) */
        delete: operations["resetMITM"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/device/sets/{name}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Join a client set (TCP only) */
        put: operations["joinSet"];
        post?: never;
        /** Leave a client set (TCP only) */
        delete: operations["leaveSet"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/device/sets/{name}/impact": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                name: components["parameters"]["Name"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Preview a current-device membership change
         * @description Verified Ethernet LAN identity and X-Dae-API: 1 required. Does not change membership. Supply flow for before/after routing analysis.
         */
        post: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    name: components["parameters"]["Name"];
                };
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["ClientImpactRequest"];
                };
            };
            responses: {
                /** @description Membership impact */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ClientImpact"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/device/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read the direct LAN caller's identity and upstream runtime statistics */
        get: operations["getDeviceStatus"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/devices/{mac}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Nonzero unicast Ethernet MAC. */
                mac: components["parameters"]["MAC"];
            };
            cookie?: never;
        };
        /**
         * Get saved device settings by MAC
         * @description Management authorization required. A null MITM override means configuration defaults, whose effective value may depend on source IP.
         */
        get: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    /** @description Nonzero unicast Ethernet MAC. */
                    mac: components["parameters"]["MAC"];
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Saved device settings */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ManagedDevice"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/devices/{mac}/mitm": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Nonzero unicast Ethernet MAC. */
                mac: components["parameters"]["MAC"];
            };
            cookie?: never;
        };
        get?: never;
        /**
         * Set a device MITM override
         * @description Management authorization, X-Dae-API: 1 and X-Dae-MITM containing the current CA fingerprint required.
         */
        put: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    /** @description Nonzero unicast Ethernet MAC. */
                    mac: components["parameters"]["MAC"];
                };
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["SetMITMRequest"];
                };
            };
            responses: {
                /** @description Updated device */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ManagedDevice"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        post?: never;
        /**
         * Restore a device's configured MITM default
         * @description Management authorization, X-Dae-API: 1, X-Dae-MITM containing the current CA fingerprint and an empty body required.
         */
        delete: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    /** @description Nonzero unicast Ethernet MAC. */
                    mac: components["parameters"]["MAC"];
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Updated device */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ManagedDevice"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/diagnostics/explain": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Explain using administrator-supplied context
         * @description Management authorization and X-Dae-API: 1 required. Read-only, 64 KiB request limit. Missing context produces incomplete results, never fabricated zero-valued identity.
         */
        post: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["ExplainRequest"];
                };
            };
            responses: {
                /** @description Explanation */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ExplainResponse"];
                    };
                };
                default: components["responses"]["Error"];
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/operations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Queue a daemon configuration operation
         * @description Requires administration. Returns a unique operation ID immediately; poll GET /api/operations/{id} for the result. Reload reads configuration from disk; suspend disables interception; refresh uses the accepted configuration. Operations execute serially. The queue holds at most 16 pending operations; a full queue or a duplicate pending refresh returns 409. A nonzero expected_pid must match the daemon PID. Local Unix operation routes remain available throughout plane replacement.
         */
        post: operations["submitOperation"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/operations/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read one daemon operation
         * @description Requires administration and an empty body. IDs are unique across restarts. The daemon retains the 64 most recently finished operations plus active and queued work; unknown or expired IDs return 404. A client timeout does not cancel accepted work.
         */
        get: operations["operation"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/plugins/{instance}/scripts/run": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Trigger an existing cron or generic task
         * @description Requires administration. Returns 202 with an acceptance snapshot and per-task run number; execution belongs to the daemon and continues after the HTTP response. Inspect the plugin status for completion. Concurrent triggers for a waiting/running task return 409. Does not change its timer schedule. Unknown task/instance: 404; ambiguous name: 400; inactive worker: 503. No inline scripts, source URLs, argument overrides or automatic retries.
         */
        post: operations["triggerScript"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/probes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Request configured outbound connectivity probes
         * @description Requires administration. Uses the outbound's configured DNS probe, existing concurrency bounds and timeouts. No arbitrary URL, network, or timeout overrides are accepted. node_id selects one path; omission or an empty value selects all paths. Returns 202 immediately with accepted IDs; repeated requests for queued/running work coalesce. Selector results are available through GET /api/selectors (checking/tested/checked_at/healthy/latency_ms); other outbounds publish their runtime health and latency through GET /api/status. This is not a persistent probe job and does not change selection or monitoring configuration. Unknown outbound: 404; invalid node/body: 400; unchecked builtin: 409.
         */
        post: operations["probe"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/resources": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read the latest resource refresh and next automatic check
         * @description Requires administration. Reports the latest API or automatic refresh. History is reset on daemon restart. Empty request body.
         */
        get: operations["resourceRefreshStatus"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/resources/refresh": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Refresh subscriptions, modules and dependencies
         * @description Requires administration and an empty request body. Uses the accepted configuration and attempts all downloads regardless of update intervals; does not read configuration edits from disk. Returns 202 immediately; poll GET /api/operations/{id} for this request’s completion. Concurrent queued/running refreshes return 409. Refreshes and reloads publish serially. Invalid candidates leave the current runtime active; available validated snapshots can be used on download failure.
         */
        post: operations["refreshResources"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/selectors": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List manual selectors (requires administration)
         * @description On TCP, a configured global.api_key requires a Bearer credential or valid browser session. When the key is empty, only a verified LAN connection is administrative (direct Ethernet peer or IP ingress on global.lan_interface), without credentials; failed LAN identification returns 403. A filesystem-authorized Unix socket connection is already administrative.
         */
        get: operations["getSelectors"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/selectors/{group}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /**
         * Override a selector
         * @description On TCP, a configured global.api_key requires a Bearer credential or valid browser session. When the key is empty, only a verified LAN connection is administrative (direct Ethernet peer or IP ingress on global.lan_interface), without credentials; failed LAN identification returns 403. A filesystem-authorized Unix socket connection is already administrative.
         */
        put: operations["selectNode"];
        post?: never;
        /**
         * Restore an explicitly configured selector(n) default; 409 when none exists
         * @description On TCP, a configured global.api_key requires a Bearer credential or valid browser session. When the key is empty, only a verified LAN connection is administrative (direct Ethernet peer or IP ingress on global.lan_interface), without credentials; failed LAN identification returns 403. A filesystem-authorized Unix socket connection is already administrative.
         */
        delete: operations["resetSelector"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/session": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /**
         * Create a browser session
         * @description With a configured global.api_key, requires Authorization: Bearer <api_key>, including on Unix, and issues a signed seven-day session cookie without the API key. Missing/incorrect credentials return 401. Without a configured key, requires verified LAN ingress or filesystem-authorized Unix access, returns 204 and clears stale cookies without issuing a session; failed LAN identification returns 403. Empty request body.
         */
        put: operations["login"];
        post?: never;
        /**
         * Clear the browser session cookie
         * @description Empty request body. Clears the caller's cookie even if its session is expired. Does not require authentication.
         */
        delete: operations["logout"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read the runtime snapshot
         * @description On TCP, a configured global.api_key requires a Bearer credential or valid browser session. When the key is empty, only a verified LAN connection is administrative (direct Ethernet peer or IP ingress on global.lan_interface), without credentials; failed LAN identification returns 403. A filesystem-authorized Unix socket connection is already administrative.
         */
        get: operations["getStatus"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/ca.cer": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Download public CA material; 404 when unavailable */
        get: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Certificate download */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/pkix-cert": string;
                    };
                };
                /** @description Certificate unavailable */
                404: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/ca.mobileconfig": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Download public CA material; 404 when unavailable */
        get: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Certificate download */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/x-apple-aspen-config": string;
                    };
                };
                /** @description Certificate unavailable */
                404: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/ca.pem": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Download public CA material; 404 when unavailable */
        get: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Certificate download */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/x-pem-file": string;
                    };
                };
                /** @description Certificate unavailable */
                404: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Availability: {
            alive: boolean;
            /** Format: date-time */
            alive_since: string;
            /** Format: int64 */
            checks_failed: number;
            /** Format: int64 */
            checks_since_alive: number;
            /** Format: int64 */
            checks_total: number;
            /** Format: date-time */
            last_check_at: string;
            /** Format: date-time */
            last_connection_failure_at: string;
            /**
             * Format: int64
             * @description Duration in nanoseconds.
             */
            last_failure_duration: number;
            /** Format: date-time */
            last_failure_started_at: string;
            recent_24h: components["schemas"]["AvailabilityWindow"];
            seen: boolean;
            /** Format: double */
            up_ratio: number;
        };
        AvailabilityWindow: {
            /** Format: int64 */
            checks_failed: number;
            /** Format: int64 */
            checks_total: number;
            /** Format: double */
            up_ratio: number;
        };
        /** @description Process-wide MITM body buffer budget. Byte counters measure reserved buffer storage; denied counts rejected reservations. */
        BufferMemoryStatus: {
            /** @description Rejected reservation count over the process lifetime (unsigned 64-bit integer). */
            denied: number;
            /**
             * Format: int64
             * @description Configured byte limit. Lowering it does not revoke existing reservations, so used may temporarily exceed limit.
             */
            limit: number;
            /**
             * Format: int64
             * @description Peak reserved bytes over the process lifetime.
             */
            peak: number;
            /**
             * Format: int64
             * @description Currently reserved bytes.
             */
            used: number;
        };
        Certificate: {
            fingerprint: string;
            name: string;
            test_available: boolean;
            /** @description Current diagnostic generation. Discard browser test results when this changes. */
            test_generation?: string;
            /** @description Exact virtual HTTPS origins allowed for MITM challenges. CA challenges use HTTPS on the current API socket. */
            test_mitm_origins?: string[];
        };
        /** @description A one-minute browser challenge bound to the verified caller and current configuration. Observations are not a device-wide CA trust verdict; the browser must receive and validate the matching proof over HTTPS with normal certificate verification. */
        CertificateTest: {
            ca_fingerprint: string;
            /** Format: date-time */
            expires_at: string;
            id: string;
            mitm_enabled: boolean;
            mitm_observed: boolean;
            mitm_url: string;
            /** Format: date-time */
            started_at: string;
            trust_observed: boolean;
            trust_url: string;
        };
        CertificateTestProof: {
            ca_fingerprint: string;
            id: string;
            /** @enum {string} */
            stage: "trust" | "mitm";
        };
        ClientGroup: {
            description: string;
            ipset?: string;
            members: string[];
            name: string;
            nftset?: string;
        };
        ClientGroups: {
            groups: components["schemas"]["ClientGroup"][];
        };
        /** @description References to the client group in active rules, not a flow evaluation. Rules have status referenced; policy_match reports applicability from the ingress context, without evaluating destination conditions or rule order. Policy flow and outbound rules retain each policy occurrence, while global system or plugin references appear once without a policy. Conditions report membership predicate values before and after the proposal. Supply flow for a separate before/after trace. */
        ClientImpact: {
            connection_behavior: string;
            exports: string[];
            generation: number;
            joined_after: boolean;
            joined_before: boolean;
            name: string;
            rules: components["schemas"]["ExplainStep"][];
            trace?: components["schemas"]["ExplainResponse"];
        };
        ClientImpactRequest: {
            context: components["schemas"]["DiagnosticContext"];
            flow?: components["schemas"]["DiagnosticFlow"];
            joined: boolean;
        };
        ClientSetState: {
            description: string;
            joined: boolean;
            name: string;
        };
        DeviceContext: {
            context: components["schemas"]["DiagnosticContext"];
            device?: components["schemas"]["DeviceState"];
            fields: components["schemas"]["DiagnosticField"][];
            generation: number;
        };
        DeviceOutboundStatus: {
            name: string;
            stats: components["schemas"]["PathStats"];
        };
        DeviceState: {
            mac: string;
            mitm?: components["schemas"]["MITMState"] | null;
            sets: components["schemas"]["ClientSetState"][];
            source_ip: string;
        };
        /** @description The requesting device's MAC-attributed upstream paths. IPv4 and IPv6 share the MAC identity. Counters survive reload and reset on daemon restart. Kernel passthrough, local HTTP/DNS responses and daemon-originated work are excluded; splice deltas are included. */
        DeviceStatus: {
            device: components["schemas"]["DeviceState"];
            /** Format: int64 */
            direct_fallback_connections: number;
            networks: components["schemas"]["PathStats"][];
            outbounds: components["schemas"]["DeviceOutboundStatus"][];
            /** @enum {string} */
            scope: "userspace_upstream";
            /** Format: date-time */
            started_at: string;
            stats: components["schemas"]["PathStats"];
        };
        DiagnosticAssumptions: {
            bindings?: components["schemas"]["DiagnosticBinding"][];
            client_sets?: {
                [key: string]: boolean;
            };
            mitm?: boolean;
            outbounds?: {
                [key: string]: boolean;
            };
        };
        DiagnosticBinding: {
            domains: string[];
            ip: string;
        };
        DiagnosticContext: {
            dscp?: number;
            ifindex?: number;
            interface?: string;
            /**
             * @description IP ingress has no Ethernet identity; an omitted link type means unknown.
             * @enum {string}
             */
            link_type?: "ethernet" | "ip";
            mac?: string;
            mark?: number;
            /** @enum {string} */
            origin?: "lan" | "local" | "daemon";
            physical_ifindex?: number;
            policy?: string;
            process_name?: string;
            source_ip?: string;
            source_port?: number;
        };
        DiagnosticDNS: {
            answer_ips?: string[];
            cd?: boolean;
            class?: string;
            do?: boolean;
            name: string;
            rcode?: number;
            rd?: boolean;
            type?: string;
            udp_size?: number;
            upstream?: string;
        };
        DiagnosticField: {
            name: string;
            source: string;
            value: string;
        };
        DiagnosticFlow: {
            destination: components["schemas"]["DiagnosticTarget"];
            http?: components["schemas"]["DiagnosticHTTP"];
            /** @enum {string} */
            protocol?: "tcp" | "udp";
            sni?: string;
        };
        DiagnosticHTTP: {
            headers?: {
                [key: string]: string[];
            };
            host?: string;
            method?: string;
            response_headers?: {
                [key: string]: string[];
            };
            response_status?: number;
            url: string;
        };
        DiagnosticSource: {
            column?: number;
            expression: string;
            file?: string;
            line?: number;
        };
        DiagnosticTarget: {
            domain?: string;
            ip?: string;
            port?: number;
        };
        DomainEvidence: {
            domain: string;
            ip: string;
            resident: boolean;
            /** Format: date-time */
            retain_until?: string;
            source: string;
        };
        ExplainCondition: {
            actual: string;
            expected: string;
            expression: string;
            match: string;
            reason: string;
            status: string;
        };
        ExplainDecision: {
            capture?: string[];
            complete: boolean;
            mark: number;
            missing?: string[];
            must: boolean;
            original_outbound?: string;
            original_target?: string;
            outbound?: string;
            policy?: string;
            rule_id?: string;
            targets?: string[];
            verdict: string;
        };
        ExplainNode: {
            id: string;
            name: string;
            reason: string;
            selected: boolean;
            selection?: components["schemas"]["SelectionStatus"];
            usable: boolean;
        };
        ExplainOutbound: {
            available: boolean;
            name: string;
            network: string;
            nodes: components["schemas"]["ExplainNode"][];
            /** Format: date-time */
            observed_at: string;
            policy: string;
            random: boolean;
        };
        ExplainRequest: {
            compare?: components["schemas"]["DiagnosticAssumptions"];
            context: components["schemas"]["DiagnosticContext"];
            /** @enum {string} */
            detail?: "rules" | "predicates";
            dns?: components["schemas"]["DiagnosticDNS"];
            flow: components["schemas"]["DiagnosticFlow"];
            /** @enum {string} */
            kind?: "flow" | "dns" | "domain" | "outbound" | "plugins";
            network?: string;
            outbound?: string;
        };
        ExplainResponse: {
            compared?: components["schemas"]["ExplainResult"];
            context: components["schemas"]["DiagnosticField"][];
            current: components["schemas"]["ExplainResult"];
            generation: number;
            /** Format: date-time */
            observed_at: string;
            /** @constant */
            schema: 1;
        };
        ExplainResult: {
            assumptions?: components["schemas"]["DiagnosticAssumptions"];
            decision: components["schemas"]["ExplainDecision"];
            domains: components["schemas"]["DomainEvidence"][];
            notes: string[];
            outbounds: components["schemas"]["ExplainOutbound"][];
            steps: components["schemas"]["ExplainStep"][];
        };
        ExplainStep: {
            action?: string;
            conditions?: components["schemas"]["ExplainCondition"][];
            expression: string;
            id: string;
            mark?: number;
            match: string;
            must?: boolean;
            outbound?: string;
            parent?: string;
            /** @description Routing policy for this occurrence; absent for a global system or plugin membership reference. */
            policy?: string;
            /**
             * @description Whether this policy is selected for the request context. Independent of the rule match; unknown when ingress is missing and multiple policies are active. Absent when there is no policy.
             * @enum {string}
             */
            policy_match?: "match" | "miss" | "unknown";
            reason: string;
            /** @description Source configuration section, such as rules or routing. */
            section?: string;
            sources?: components["schemas"]["DiagnosticSource"][];
            stage: string;
            status: string;
            targets?: string[];
        };
        /** @description Classified failure metadata; message is display text and must not be used as a metric label. */
        FailureSnapshot: {
            code?: string;
            /** Format: int64 */
            episode_id: number;
            layer: string;
            message: string;
            /** Format: date-time */
            occurred_at: string;
            origin: string;
            phase: string;
            reason: string;
            resource: components["schemas"]["ResourceRef"];
            scope: string;
        };
        GroupAvailability: {
            alive: boolean;
            /** Format: date-time */
            alive_since: string;
            /** Format: int64 */
            checks_failed: number;
            /** Format: int64 */
            checks_since_alive: number;
            /** Format: int64 */
            checks_total: number;
            /** Format: date-time */
            last_check_at: string;
            /** Format: date-time */
            last_connection_failure_at: string;
            /**
             * Format: int64
             * @description Duration in nanoseconds.
             */
            last_failure_duration: number;
            /** Format: date-time */
            last_failure_started_at: string;
            recent: components["schemas"]["GroupStateWindow"];
            recent_24h: components["schemas"]["AvailabilityWindow"];
            seen: boolean;
            /** Format: double */
            up_ratio: number;
        };
        GroupStateWindow: {
            /** @description For checked groups, 10 oldest-first buckets spanning the last hour (6 minutes each); the worst state in each bucket. Unchecked groups have no history. */
            states: ("unknown" | "available" | "unavailable")[];
        };
        GroupStatus: {
            availability: components["schemas"]["GroupAvailability"];
            check_async?: boolean;
            checks_connectivity: boolean;
            /** @enum {string} */
            connectivity?: "available" | "checking" | "unavailable";
            critical: boolean;
            name: string;
            /** @description Network order: tcp4, tcp6, udp4, udp6. */
            networks: components["schemas"]["PathStats"][];
            nodes: components["schemas"]["NodeStatus"][];
            policy: string;
            /** @description Network order: tcp4, tcp6, udp4, udp6. */
            selected_node_ids: string[];
            stats: components["schemas"]["PathStats"];
            /** @enum {string} */
            target_kind: "group" | "node" | "builtin";
        };
        /** @description Successful probe durations only. Failures and selection offsets are excluded; average_10 uses the last ten successful samples. */
        LatencyStats: {
            /**
             * Format: int64
             * @description Duration in nanoseconds.
             */
            average_10: number;
            /**
             * Format: int64
             * @description Duration in nanoseconds.
             */
            last: number;
            /**
             * Format: int64
             * @description Duration in nanoseconds.
             */
            moving_average: number;
        };
        ManagedDevice: {
            mac: string;
            mitm_override: boolean | null;
            sets: components["schemas"]["ClientSetState"][];
        };
        MITMState: {
            ca_fingerprint: string;
            enabled: boolean;
            override: boolean | null;
        };
        NodeAnnotationStatus: {
            add_latency?: string;
            priority?: number | null;
            priority_conditional?: boolean;
        };
        /** @description Local connection to the first proxy, independent of destination network support. */
        NodeEgress: {
            interface?: string;
            /** @enum {integer} */
            ipversion: 0 | 4 | 6;
            mark: number;
        };
        NodeStatus: {
            address: string;
            annotation?: components["schemas"]["NodeAnnotationStatus"] | null;
            availability: components["schemas"]["Availability"];
            checks_connectivity: boolean;
            confirming_failure: boolean;
            /** @description The physical transport has been released and is not being recreated. Omitted when false; independent of group-local selection tracking. */
            dormant?: boolean;
            egress?: components["schemas"]["NodeEgress"];
            failure?: components["schemas"]["FailureSnapshot"];
            healthy: boolean;
            id: string;
            latency?: components["schemas"]["LatencyStats"] | null;
            name: string;
            /** Format: int64 */
            observed_session_seq: number;
            protocol: string;
            recovery: components["schemas"]["RecoverySnapshot"];
            /** Format: int64 */
            revision: number;
            selection?: components["schemas"]["SelectionStatus"];
            session_detail?: components["schemas"]["SessionStatus"];
            stats: components["schemas"]["PathStats"];
            subtag: string;
            /** @description Network order: tcp4, tcp6, udp4, udp6. */
            support: ("unknown" | "confirmed" | "unsupported")[];
        };
        Operation: {
            error?: string;
            /** Format: date-time */
            finished_at?: string;
            id: string;
            /** @enum {string} */
            kind: "reload" | "suspend" | "refresh";
            progress?: string;
            /** Format: date-time */
            queued_at: string;
            result?: string;
            /** Format: date-time */
            started_at?: string;
            /** @enum {string} */
            state: "queued" | "running" | "completed" | "failed" | "canceled";
            /** @enum {string} */
            trigger: "api" | "automatic" | "signal";
        };
        OperationRequest: {
            /** @description Abort established connections during reload or suspend; invalid for refresh. */
            abort?: boolean;
            /** @description When nonzero, require the daemon PID to match. */
            expected_pid?: number;
            /** @enum {string} */
            kind: "reload" | "suspend" | "refresh";
        };
        PathStats: {
            /** Format: int64 */
            active_connections: number;
            /** @description Unsigned 64-bit count; JavaScript clients must account for integer precision above 2^53-1. */
            download_bytes: number;
            history: components["schemas"]["TrafficHistory"];
            /** Format: int64 */
            total_connections: number;
            /** @description Unsigned 64-bit count; JavaScript clients must account for integer precision above 2^53-1. */
            upload_bytes: number;
        };
        PluginInstanceStatus: {
            /** @description Optional process-wide budget snapshot, repeated on each instance. Do not sum it across instances. */
            buffer_memory?: components["schemas"]["BufferMemoryStatus"];
            /** Format: int64 */
            destination_rules: number;
            /** @description Opaque plugin-defined JSON report. Its schema belongs to the plugin; reports exclude configuration credentials. */
            details?: unknown;
            id: string;
            /** Format: int64 */
            scopes: number;
            state: string;
            type: string;
        };
        ProbeRequest: {
            /** @description Path ID within that outbound. Empty or omitted probes every path once. */
            node_id?: string;
            /** @description Name of an instantiated, checked outbound. Applies to selector and automatic policies, and checked direct-node targets. */
            outbound: string;
        };
        ProbeResponse: {
            /** @description Accepted targets, including requests coalesced with queued/running checks. Acceptance is not a health result. */
            node_ids: string[];
            outbound: string;
        };
        RecoverySnapshot: {
            action?: string;
            /** Format: int64 */
            attempt: number;
            blocked_by?: string;
            executor?: string;
            /** @enum {string} */
            phase: "cleanup" | "waiting_dependency" | "queued" | "backoff" | "connecting" | "verifying" | "ready" | "blocked" | "stopped";
            /**
             * Format: date-time
             * @description Actual timer deadline, present only during backoff. Omitted when no retry timer is owned.
             */
            retry_at?: string;
            verification: string;
        };
        /** @description Unsigned resource identifiers; generations are comparable only within the same owner and resource. */
        ResourceRef: {
            /** Format: int64 */
            generation: number;
            /** Format: int64 */
            owner_id: number;
            /** Format: int64 */
            resource_id: number;
        };
        ResourceRefreshStatus: {
            /** Format: date-time */
            next_check?: string;
            operation?: components["schemas"]["Operation"];
        };
        SavedSelectorSelection: {
            /** @description Saved logical path name, including its entrance choice. */
            name: string;
            /**
             * @description Missing or ambiguous preferences remain saved while the startup choice is used temporarily.
             * @enum {string}
             */
            status: "matched" | "missing" | "ambiguous";
        };
        ScriptRunRequest: {
            /** @description Required when the script name is not unique within the instance. */
            module?: string;
            script: string;
        };
        ScriptRunResponse: {
            instance: string;
            module: string;
            run: number;
            status: components["schemas"]["ScriptTaskStatus"];
        };
        /** @description A plugin-managed script task. Times describe the latest scheduled or manual attempt, including execution-slot waits. Only cron has a schedule and timezone; generic is ready when idle and active. Runtime success does not imply application-level success; errors are credential-free categories. Counters and history reset on reload. */
        ScriptTaskStatus: {
            cronexp?: string;
            failures: number;
            /** Format: int64 */
            last_duration_ms: number;
            /** @description Stable failure category, such as timeout, canceled, error or http_client_unavailable. No raw script exceptions or response bodies. */
            last_error?: string;
            /** Format: date-time */
            last_finished_at?: string;
            /** @enum {string} */
            last_result?: "success" | "failed";
            /** Format: date-time */
            last_started_at?: string;
            /** @enum {string} */
            last_trigger?: "cron" | "http-api";
            name: string;
            /** Format: date-time */
            next_run?: string;
            runs: number;
            /** @description Schedule ticks skipped because this task was still waiting or running. */
            skipped: number;
            /** @enum {string} */
            state: "pending" | "ready" | "scheduled" | "waiting" | "running" | "unscheduled" | "stopped";
            timeout_seconds: number;
            timezone?: string;
            /** @enum {string} */
            type: "cron" | "generic";
        };
        SelectionStatus: {
            degraded: boolean;
            /**
             * Format: int64
             * @description Required recovery observation duration, in nanoseconds.
             */
            failure_recovery: number;
            /** Format: date-time */
            measured_at?: string;
            priority: number;
            /**
             * Format: int64
             * @description Successfully verified observation time, in nanoseconds.
             */
            recovery_elapsed: number;
            /**
             * Format: int64
             * @description Selection score in nanoseconds; may be negative.
             */
            score: number;
            /**
             * @description Group-local scheduling role. Standby paths may still be monitored by another group; active operations are reported by recovery.
             * @enum {string}
             */
            tracking: "selected" | "monitoring" | "standby";
        };
        SelectNodeRequest: {
            node_id: string;
        };
        SelectorNode: {
            /**
             * Format: date-time
             * @description Completion time of the last test; absent before the first completed test. Untracked results are historical.
             */
            checked_at?: string;
            /** @description A test is queued/running, or the monitored node awaits its initial check. Untested dormant nodes are not checking. */
            checking: boolean;
            egress?: components["schemas"]["NodeEgress"];
            healthy: boolean;
            id: string;
            latency_ms?: number | null;
            name: string;
            tested: boolean;
            /** @description Automatic connectivity checks are enabled. */
            tracking: boolean;
        };
        SelectorsResponse: {
            admin_enabled: boolean;
            /**
             * @description The request's administrative access mode: configured API key/session, verified LAN ingress with no configured key, or filesystem-authorized Unix socket. LAN access is revalidated for every request and creates no browser session.
             * @enum {string}
             */
            auth_mode: "api_key" | "lan" | "unix";
            selectors: components["schemas"]["SelectorState"][];
        };
        SelectorState: {
            /** @description Present only for an explicitly indexed selector(n). Plain selector has no configured default and cannot be reset. */
            default_node_id?: string;
            name: string;
            node_id: string;
            nodes: components["schemas"]["SelectorNode"][];
            /** @description A saved preference exists, including when it is temporarily missing or ambiguous. */
            overridden: boolean;
            saved_selection?: components["schemas"]["SavedSelectorSelection"];
            /** @description Read-only group track_all configuration. False by default: only the selected node is monitored. Configure the file and reload to change it. */
            track_all: boolean;
        };
        SessionStatus: {
            accepting: boolean;
            /** Format: int64 */
            episode_id: number;
            /** Format: int64 */
            readiness_version: number;
            recovery_required: boolean;
            resource: components["schemas"]["ResourceRef"];
            /** Format: int64 */
            seq: number;
            /** @enum {string} */
            state: "disconnected" | "connecting" | "connected" | "closed";
            /** Format: int64 */
            usable_capacity: number;
        };
        SetMITMRequest: {
            enabled: boolean;
        };
        StatusSnapshot: {
            /**
             * Format: int64
             * @description Process-lifetime count of established no-connectivity fallbacks to direct; preserved across reloads. Not a per-path or per-node counter.
             */
            direct_fallback_connections: number;
            groups: components["schemas"]["GroupStatus"][];
            /** Format: date-time */
            last_reload_at: string;
            /** @description Network order: tcp4, tcp6, udp4, udp6. */
            networks: components["schemas"]["PathStats"][];
            plugins?: components["schemas"]["PluginInstanceStatus"][];
            /**
             * Format: int64
             * @constant
             */
            schema: 12;
            /** Format: date-time */
            started_at: string;
            stats: components["schemas"]["PathStats"];
            tables: components["schemas"]["TableUsage"][];
            version: string;
        };
        TableUsage: {
            breakdown?: components["schemas"]["TableUsageBreakdown"] | null;
            /**
             * Format: int64
             * @description IP states with a nonzero domain bitmap before capacity selection. candidates - used is the number excluded by kernel capacity.
             */
            candidates?: number;
            /** Format: int64 */
            limit: number;
            name: string;
            /** @description Pending kernel projection updates or removals. */
            pending?: number;
            /**
             * Format: int64
             * @description Resident IP count for domain-kernel; retained domain-IP pair count for domain-registry.
             */
            used: number;
        };
        TableUsageBreakdown: {
            /**
             * Format: int64
             * @description Distinct retained domain names, including evidence not projected into the kernel.
             */
            domains: number;
            /** @description Pairs removed by time-based GC, cumulative across reload and reset on cold start. Unsigned 64-bit count; JavaScript clients must account for integer precision above 2^53-1. */
            gc: number;
            /**
             * Format: int64
             * @description Distinct retained IPs across all domains; equals ipv4 + ipv6. A shared IP counts once.
             */
            ips: number;
            /**
             * Format: int64
             * @description Distinct retained IPv4 addresses, not domain-IP pairs.
             */
            ipv4: number;
            /**
             * Format: int64
             * @description Distinct retained IPv6 addresses, not domain-IP pairs.
             */
            ipv6: number;
        };
        TrafficHistory: {
            /** @description Oldest first; completed 5-second averages in bytes/second. Both directions have equal length, 0–12 samples. */
            download_bytes_per_second: number[];
            /** @description Oldest first; completed 5-second averages in bytes/second. Both directions have equal length, 0–12 samples. */
            upload_bytes_per_second: number[];
        };
    };
    responses: {
        /** @description 400 invalid request; 401 missing/incorrect configured API key or invalid/expired session; 403 forbidden or unverified LAN identity when no API key is configured; 404 absent resource; 405 unsupported method; 409 CA changed; 413 body over endpoint limit (1 KiB, or 64 KiB for diagnostics); 415 wrong media type; 500 persistence failure; 503 starting/reloading. Route/method errors and missing certificates may be plain text. */
        Error: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    error: string;
                };
                "text/plain": string;
            };
        };
    };
    parameters: {
        /** @description Nonzero unicast Ethernet MAC. */
        MAC: string;
        Name: string;
    };
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    getCertificate: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Certificate"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    getDevice: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeviceState"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    startCertificateTest: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Challenge created, expires in one minute */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CertificateTest"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    getCertificateTest: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Current observation; 404 for expired, replaced or foreign challenges */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CertificateTest"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    setMITM: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
                /** @description Current CA SHA-256 fingerprint. */
                "X-Dae-MITM": string;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SetMITMRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeviceState"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    resetMITM: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
                /** @description Current CA SHA-256 fingerprint. */
                "X-Dae-MITM": string;
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeviceState"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    joinSet: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path: {
                /** @description URL-encoded name, including any slash. */
                name: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeviceState"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    leaveSet: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path: {
                /** @description URL-encoded name, including any slash. */
                name: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeviceState"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    getDeviceStatus: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeviceStatus"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    submitOperation: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["OperationRequest"];
            };
        };
        responses: {
            /** @description Operation queued */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Operation"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    operation: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Operation status */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Operation"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    triggerScript: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path: {
                instance: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ScriptRunRequest"];
            };
        };
        responses: {
            /** @description Script execution accepted */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScriptRunResponse"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    probe: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProbeRequest"];
            };
        };
        responses: {
            /** @description Probe targets accepted */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProbeResponse"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    resourceRefreshStatus: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Resource refresh status */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResourceRefreshStatus"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    refreshResources: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Resource refresh queued */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Operation"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    getSelectors: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SelectorsResponse"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    selectNode: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path: {
                /** @description URL-encoded name, including any slash. */
                group: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SelectNodeRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SelectorState"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    resetSelector: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path: {
                /** @description URL-encoded name, including any slash. */
                group: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SelectorState"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
    login: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Access verified; no response body */
            204: {
                headers: {
                    /** @description With a configured key: dae_session; Path=/api; HttpOnly; SameSite=Strict; Max-Age=604800. Without a key: expires any stale dae_session cookie instead. */
                    "Set-Cookie"?: string;
                    [name: string]: unknown;
                };
                content?: never;
            };
            default: components["responses"]["Error"];
        };
    };
    logout: {
        parameters: {
            query?: never;
            header: {
                "X-Dae-API": "1";
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Cookie cleared; no response body */
            204: {
                headers: {
                    /** @description Expires the dae_session cookie at Path=/api */
                    "Set-Cookie"?: string;
                    [name: string]: unknown;
                };
                content?: never;
            };
            default: components["responses"]["Error"];
        };
    };
    getStatus: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StatusSnapshot"];
                };
            };
            default: components["responses"]["Error"];
        };
    };
}
