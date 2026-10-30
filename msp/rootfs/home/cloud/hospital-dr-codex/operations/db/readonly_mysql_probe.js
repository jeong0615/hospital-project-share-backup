"use strict";

// Read-only pre-switch check. The password is read from a root-only temporary
// JSON file, never from argv or logs. This runs inside each existing app image,
// which already contains mysql2 and uses the same Docker network path as the app.
const fs = require("fs");
// Both immutable app images install mysql2 under this work directory.
const mysql = require("/app/node_modules/mysql2/promise");

async function main() {
  let config;
  try {
    config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  } catch (_) {
    process.stderr.write("DB_ENDPOINT_PROBE=BLOCKED reason=CONFIG_UNAVAILABLE\n");
    process.exitCode = 2;
    return;
  }

  if (
    !config ||
    !/^10\.20\.30\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/.test(config.host) ||
    config.host === "IP_REDACTED" ||
    config.port !== 3307 ||
    config.user !== "hospital_dr_service" ||
    config.database !== "hospital_db" ||
    typeof config.password !== "string" ||
    config.password.length < 32
  ) {
    process.stderr.write("DB_ENDPOINT_PROBE=BLOCKED reason=TARGET_OR_ACCOUNT_INVALID\n");
    process.exitCode = 2;
    return;
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: config.host,
      port: config.port,
      user: config.user,
      password: "<SET_IN_SECRET_STORE>",
      database: config.database,
      connectTimeout: 5000,
      multipleStatements: false,
    });
    const [rows] = await connection.query(
      "SELECT 1 AS ok, @@port AS port, @@read_only AS read_only, " +
      "@@super_read_only AS super_read_only, DATABASE() AS db_name"
    );
    const row = rows && rows[0];
    if (
      !row || row.ok !== 1 || Number(row.port) !== 3307 ||
      Number(row.read_only) !== 1 || Number(row.super_read_only) !== 1 ||
      row.db_name !== "hospital_db"
    ) {
      process.stderr.write("DB_ENDPOINT_PROBE=BLOCKED reason=READ_ONLY_DB_CONTRACT_MISMATCH\n");
      process.exitCode = 3;
      return;
    }
    process.stdout.write("DB_ENDPOINT_PROBE=PASS read_only=true super_read_only=true\n");
  } catch (_) {
    process.stderr.write("DB_ENDPOINT_PROBE=BLOCKED reason=SERVICE_ACCOUNT_CONNECTION_FAILED\n");
    process.exitCode = 4;
  } finally {
    if (connection) {
      try { await connection.end(); } catch (_) { /* no sensitive details */ }
    }
    config.password = "";
  }
}

main().catch(() => {
  process.stderr.write("DB_ENDPOINT_PROBE=BLOCKED reason=PROBE_INTERNAL_ERROR\n");
  process.exitCode = 5;
});
