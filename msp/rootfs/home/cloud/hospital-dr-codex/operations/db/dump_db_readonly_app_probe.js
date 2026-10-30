"use strict";

// Runs inside the already-fenced application container. It issues only SELECT
// and SHOW GRANTS, and never prints query rows, credentials, or patient data.
const mysql = require("/app/node_modules/mysql2/promise");

const APP_SOURCE_IP = {
  web: "IP_REDACTED",
  emr: "IP_REDACTED",
};

function fail(code) {
  process.stderr.write(`DUMP_APP_DB_PROBE=BLOCKED reason=${code}\n`);
  process.exitCode = 1;
}

function normalizedIp(value) {
  return String(value || "").replace(/^::ffff:/, "");
}

function grantsAreSelectOnly(rows) {
  if (!Array.isArray(rows) || rows.length < 2) return false;
  let usage = 0;
  let select = 0;
  for (const row of rows) {
    const grant = String(row[Object.keys(row)[0]] || "").trim();
    if (/^GRANT USAGE ON \*\.\* TO /i.test(grant)) {
      usage += 1;
      continue;
    }
    if (/^GRANT SELECT ON [`']?hospital_db[`']?\.\* TO /i.test(grant)) {
      select += 1;
      continue;
    }
    return false;
  }
  return usage === 1 && select === 1;
}

async function main() {
  const kind = process.env.DR_EXPECTED_APP_KIND;
  const expectedHost = process.env.DR_EXPECTED_DB_HOST;
  const expectedUuid = String(process.env.DR_EXPECTED_DB_SERVER_UUID || "").toLowerCase();
  const expectedUser = "hospital_dr_service";
  const expectedPort = 3307;
  const expectedSource = APP_SOURCE_IP[kind];
  if (
    !expectedSource ||
    !/^10\.20\.30\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/.test(expectedHost || "") ||
    expectedHost === "IP_REDACTED" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(expectedUuid) ||
    process.env.DB_HOST !== expectedHost ||
    Number(process.env.DB_PORT) !== expectedPort ||
    process.env.DB_USER !== expectedUser ||
    process.env.DB_NAME !== "hospital_db" ||
    !process.env.DB_PASSWORD
  ) {
    fail("APP_DB_ENDPOINT_CONTRACT_INVALID");
    return;
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: expectedPort,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      connectTimeout: 5000,
      multipleStatements: false,
    });
    const peer = normalizedIp(connection.connection?.stream?.remoteAddress);
    const [identityRows] = await connection.query(
      "SELECT @@server_uuid AS server_uuid, @@hostname AS hostname, @@port AS port, " +
        "@@read_only AS read_only, @@super_read_only AS super_read_only, " +
        "DATABASE() AS db_name, CURRENT_USER() AS current_user"
    );
    const identity = identityRows && identityRows[0];
    if (
      peer !== expectedHost ||
      !identity ||
      String(identity.server_uuid).toLowerCase() !== expectedUuid ||
      !identity.hostname ||
      Number(identity.port) !== expectedPort ||
      Number(identity.read_only) !== 0 ||
      Number(identity.super_read_only) !== 0 ||
      identity.db_name !== "hospital_db" ||
      identity.current_user !== `${expectedUser}@${expectedSource}`
    ) {
      fail("CONNECTED_DB_IDENTITY_MISMATCH");
      return;
    }
    const [grantRows] = await connection.query("SHOW GRANTS FOR CURRENT_USER()");
    if (!grantsAreSelectOnly(grantRows)) {
      fail("APP_DB_ACCOUNT_NOT_SELECT_ONLY");
      return;
    }
    process.stdout.write("DUMP_APP_DB_PROBE=PASS identity=true privileges=SELECT_ONLY\n");
  } catch (_) {
    fail("READONLY_DB_PROBE_FAILED");
  } finally {
    if (connection) {
      try { await connection.end(); } catch (_) { /* omit connection details */ }
    }
  }
}

main().catch(() => fail("READONLY_DB_PROBE_INTERNAL_ERROR"));
