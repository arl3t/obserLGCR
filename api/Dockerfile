# obserLGCR API — fork demo (solo Postgres, sin auth).
FROM node:22-alpine
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# Código (slim server + módulos exportados + cimientos compartidos)
COPY . .

EXPOSE 8787
# Espera PG → migraciones (idempotente) → API. Sin PG no arranca (evita login 500).
CMD ["sh", "-c", "node scripts/wait-for-postgres.mjs && (node migrate.mjs || true) && exec node server.mjs"]
