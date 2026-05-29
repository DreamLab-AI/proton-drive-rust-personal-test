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

const PREVIEW = 1024;

async function probe(name, path) {
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
        const result = { name, status: resp.status, ok: resp.ok, body_preview: preview };
        console.log(JSON.stringify(result));
        return { ok: resp.ok, text };
    } catch (e) {
        console.log(JSON.stringify({
            name,
            status: 0,
            ok: false,
            error: String(e?.message ?? e),
        }));
        return { ok: false, text: "" };
    }
}

function extractFirstVolumeId(body) {
    try {
        const parsed = JSON.parse(body);
        const arr = Array.isArray(parsed) ? parsed : parsed?.Shares;
        return arr?.[0]?.VolumeID ?? null;
    } catch {
        return null;
    }
}

await probe("get_users", "core/v4/users");
const shares = await probe("list_shares", "drive/shares");
const volumeId = shares.ok ? extractFirstVolumeId(shares.text) : null;
const eventPath = volumeId
    ? `drive/volumes/${volumeId}/events/latest`
    : "drive/volumes/UNKNOWN/events/latest";
await probe("get_latest_event_id", eventPath);
