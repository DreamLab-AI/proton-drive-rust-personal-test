#!/usr/bin/env node
// Tier A "JS backend" for pdtui probe: raw `fetch` against the same endpoints
// the Rust probe hits, using the same session.json. No SDK dependency.
//
// Purpose: produce a side-by-side reference output so we can diff Rust vs JS
// for the M1 (DTO) + M3 (HTTP) layers without involving crypto.
//
// Usage:  node scripts/js-probe.mjs
// Output: one JSON object per probe on stdout (same shape as pdtui probe).

import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const cfg = process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config");
const sessionPath = join(cfg, "pdtui", "session.json");

let session;
try {
    session = JSON.parse(await readFile(sessionPath, "utf8"));
} catch (e) {
    console.error(`no session at ${sessionPath} (${e.code ?? e.message})`);
    process.exit(2);
}

const baseUrl = session.base_url ?? session.BaseUrl ?? "https://drive.proton.me/api";
const appVersion =
    session.app_version ??
    session.AppVersion ??
    "external-drive-pdtui@0.0.1-stable";

const PROBES = [
    ["get_users", "core/v4/users"],
    ["list_shares", "drive/shares"],
    ["get_latest_event_id", "drive/v2/events/latest"],
];

const PREVIEW = 1024;

for (const [name, path] of PROBES) {
    const url = `${baseUrl.replace(/\/$/, "")}/${path}`;
    try {
        const resp = await fetch(url, {
            method: "GET",
            headers: {
                Authorization: `Bearer ${session.AccessToken ?? session.access_token}`,
                "x-pm-uid": session.UID ?? session.uid,
                "x-pm-appversion": appVersion,
                accept: "application/json",
            },
        });
        const text = await resp.text();
        const preview = text.slice(0, PREVIEW);
        console.log(JSON.stringify({
            name,
            status: resp.status,
            ok: resp.ok,
            body_preview: preview,
        }));
    } catch (e) {
        console.log(JSON.stringify({
            name,
            status: 0,
            ok: false,
            error: String(e?.message ?? e),
        }));
    }
}
