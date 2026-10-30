"use strict";

// Read-only proof that the app connects to the exact isolated DB with only the
// approved schema-scoped DML privileges. This script executes SELECT only.
const mysql = require("/app/node_modules/mysql2/promise");
const SOURCE = { web: "IP_REDACTED", emr: "IP_REDACTED" };

function fail(code) {
  process.stderr.write(`DUMP_SERVICE_OPEN_APP_PROBE=BLOCKED reason=${code}\n`);
  process.exitCode = 1;
}

function grantsAreExact(rows, source) {
  if (!Array.isArray(rows) || rows.length !== 2) return false;
  const grants = rows.map((row) => String(row[Object.keys(row)[0]] || "").trim()
    .replace(/[\x60']/g, "")
    .replace(/\s+/g, " ")
    .toUpperCase());
  const expectedUser = `HOSPITAL_DR_SERVICE@${source}`;
  let usage = 0;
  let schema = 0;
  for (const grant of grants) {
    if (grant === `GRANT USAGE ON *.* TO ${expectedUser}`) {
      usage += 1;
      continue;
    }
    const match = grant.match(new RegExp(`^GRANT ([A-Z, ]+) ON HOSPITAL_DB\\.\\* TO ${expectedUser}$`));
    if (!match) return false;
    const privileges = match[1].split(",").map((item) => item.trim().toUpperCase()).sort();
    if (JSON.stringify(privileges) !== JSON.stringify(["DELETE", "INSERT", "SELECT", "UPDATE"])) return false;
    schema += 1;
  }
  return usage === 1 && schema === 1;
}

async function main() {
  const kind = process.env.DR_EXPECTED_APP_KIND;
  const host = process.env.DR_EXPECTED_DB_HOST || "";
  const uuid = String(process.env.DR_EXPECTED_DB_SERVER_UUID || "").toLowerCase();
  const source = SOURCE[kind];
  if (
    !source || !/^10\.20\.30\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/.test(host) ||
    host === "IP_REDACTED" || process.env.DB_HOST !== host || Number(process.env.DB_PORT) !== 3307 ||
    process.env.DB_USER !== "hospital_dr_service" || process.env.DB_NAME !== "hospital_db" ||
    !process.env.DB_PASSWORD || !/^[0-9a-f-]{36}$/.test(uuid)
  ) {
    fail("APP_DB_ENDPOINT_CONTRACT_INVALID");
    return;
  }
  let connection;
  try {
    connection = await mysql.createConnection({
      host, port: 3307, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
      database: "hospital_db", connectTimeout: 5000, multipleStatements: false,
    });
    const [identityRows] = await connection.query(
      "SELECT @@server_uuid AS server_uuid, @@hostname AS hostname, @@port AS port, " +
      "@@read_only AS read_only, @@super_read_only AS super_read_only, " +
      "DATABASE() AS db_name, CURRENT_USER() AS current_user"
    );
    const identity = identityRows && identityRows[0];
    if (
      !identity || String(identity.server_uuid).toLowerCase() !== uuid || Number(identity.port) !== 3307 ||
      Number(identity.read_only) !== 0 || Number(identity.super_read_only) !== 0 ||
      identity.db_name !== "hospital_db" || identity.current_user !== `hospital_dr_service@${source}`
    ) {
      fail("CONNECTED_DB_IDENTITY_MISMATCH");
      return;
    }
    const [grants] = await connection.query("SHOW GRANTS FOR CURRENT_USER()");
    if (!grantsAreExact(grants, source)) {
      fail("SERVICE_DB_GRANTS_NOT_EXACT");
      return;
    }
    process.stdout.write("DUMP_SERVICE_OPEN_APP_PROBE=PASS identity=true privileges=HOSPITAL_DB_DML\n");
  } catch (_) {
    fail("SERVICE_DB_READONLY_CONNECTION_PROBE_FAILED");
  } finally {
    if (connection) {
      try { await connection.end(); } catch (_) { /* no secrets or server data */ }
    }
  }
}

main().catch(() => fail("SERVICE_DB_PROBE_INTERNAL_ERROR"));
