#!/usr/bin/env node
/**
 * Exporta datos NOC/inventario al layout de lake (JSONL particionado).
 * Uso: node api/scripts/export-noc-lake.mjs [YYYY-MM-DD]
 */
import { exportNocLake } from "../services/nocLakeExportService.mjs";

const dt = process.argv[2];
exportNocLake({ dt })
  .then((s) => {
    console.log(JSON.stringify(s, null, 2));
    process.exit(0);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
