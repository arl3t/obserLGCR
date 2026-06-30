# obserLGCR API — fork demo (solo Postgres, sin auth).
FROM node:22-alpine
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# Código (slim server + módulos exportados + cimientos compartidos)
COPY . .

EXPOSE 8787
# Aplica migraciones (idempotente; fallos legacy no bloquean arranque) y escucha API.
CMD ["sh", "-c", "node migrate.mjs || true; exec node server.mjs"]
