# obserLGCR Dashboard — build Vite + nginx (fork demo, sin auth).
# ─── Stage 1: build ──────────────────────────────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Sin auth (VITE_OIDC_AUTHORITY vacío → ProtectedRoute pass-through).
# VITE_API_BASE_URL vacío → rutas /api relativas proxeadas por nginx.
ARG VITE_API_BASE_URL=""
ARG VITE_OIDC_AUTHORITY=""
ARG VITE_TENANT_NAME="obserLGCR"
ARG VITE_PLATFORM_AUTH="true"
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_OIDC_AUTHORITY=$VITE_OIDC_AUTHORITY
ENV VITE_TENANT_NAME=$VITE_TENANT_NAME
ENV VITE_PLATFORM_AUTH=$VITE_PLATFORM_AUTH

RUN npm run build

# ─── Stage 2: serve ──────────────────────────────────────────────────────────
FROM nginx:1.27-alpine
COPY nginx.docker.conf /etc/nginx/nginx.conf
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
