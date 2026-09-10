#!/usr/bin/env node
// ComputeID — Audit Hash-Chain Integrity Verifier (OPAQUE diligence deliverable)
//
// Walks the ENTIRE mcp_audit_log table in order and independently recomputes
// each entry's hash, confirming the chain has not been tampered with or had
// rows deleted/reordered. This is the real, same-logic-as-production check
// (mirrors canonicalAudit + the hash construction in routes/mcpGateway.js),
// NOT a reshaped/faked field.
//
// Requires direct DB access (this is a server-side integrity check, not
// something an external party can run against an exported evidence bundle
// alone — that is an honest, inherent limitation of this specific check).

const { Client } = require('pg');
const crypto = require('crypto');

function canonicalAudit(fields) {
  const ordered = {};
  Object.keys(fields).sort().forEach((k) => { ordered[k] = fields[k] === undefined ? null : fields[k]; });
  return JSON.stringify(ordered);
}

async function verifyChain(connectionString) {
  const client = new Client({ connectionString });
  await client.connect();

  const result = await client.query(
    `SELECT id, request_id, agent_name, agent_org, agent_key_thumbprint, server_slug,
            mcp_method, tool_name, capability_used, decision, reason, http_status,
            latency_ms, prev_hash, entry_hash
     FROM mcp_audit_log ORDER BY id ASC`
  );

  let prevHash = null;
  let brokenAt = null;
  let checked = 0;

  for (const row of result.rows) {
    const hashFields = {
      request_id: row.request_id,
      agent_name: row.agent_name,
      agent_org: row.agent_org,
      agent_key_thumbprint: row.agent_key_thumbprint,
      server_slug: row.server_slug,
      mcp_method: row.mcp_method,
      tool_name: row.tool_name,
      capability_used: row.capability_used,
      decision: row.decision,
      reason: row.reason,
      http_status: row.http_status,
      latency_ms: row.latency_ms,
    };

    const h = crypto.createHash('sha256');
    if (prevHash) h.update(prevHash);
    h.update(canonicalAudit(hashFields), 'utf8');
    const recomputed = h.digest();

    const storedPrevHash = row.prev_hash;
    const storedEntryHash = row.entry_hash;

    const prevHashMatches = (prevHash === null && storedPrevHash === null) ||
      (Buffer.isBuffer(prevHash) && Buffer.isBuffer(storedPrevHash) && prevHash.equals(storedPrevHash));
    const entryHashMatches = Buffer.isBuffer(storedEntryHash) && recomputed.equals(storedEntryHash);

    checked++;

    if (!prevHashMatches || !entryHashMatches) {
      brokenAt = row.id;
      break;
    }

    prevHash = storedEntryHash;
  }

  await client.end();

  return {
    total_entries: result.rows.length,
    entries_checked: checked,
    chain_intact: brokenAt === null,
    broken_at_id: brokenAt,
  };
}

const connStr = process.argv[2];
if (!connStr) {
  console.error('Usage: node verify-audit-chain.js <postgres-connection-string>');
  process.exit(1);
}

verifyChain(connStr)
  .then((result) => console.log(JSON.stringify(result, null, 2)))
  .catch((err) => { console.error('FAILED:', err.message); process.exit(1); });
