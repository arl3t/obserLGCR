/**
 * kcAdmin.mjs — Cliente HTTP para la API Admin de Keycloak.
 *
 * Usa la URL interna Docker (keycloak:8080), nunca la URL pública, para no
 * depender del proxy externo ni de TLS desde el backend.
 *
 * Token de admin con cache en memoria (caducidad ~60 s, renovación automática).
 */

const KC_BASE  = process.env.KC_INTERNAL_URL ?? "http://keycloak:8080";
const KC_REALM = "legacyhunt-soc";
const KC_ROLE_MAP = {
  L1: "analyst", L1L2: "analyst", L2: "analyst",
  L3: "analyst",  LEADER: "manager",   ADMIN: "admin",
};

// ── Cache de token admin ───────────────────────────────────────────────────────
let _cachedToken   = null;
let _tokenExpiresAt = 0;

async function getAdminToken() {
  const now = Date.now();
  if (_cachedToken && _tokenExpiresAt - now > 10_000) return _cachedToken;

  const user = process.env.KC_ADMIN_USER     ?? "admin";
  const pass = process.env.KC_ADMIN_PASSWORD ?? "";

  const resp = await fetch(`${KC_BASE}/realms/master/protocol/openid-connect/token`, {
    method:  "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:    new URLSearchParams({
      client_id:  "admin-cli",
      username:   user,
      password:   pass,
      grant_type: "password",
    }),
  });

  if (!resp.ok) {
    const txt = await resp.text().catch(() => resp.status);
    throw new Error(`KC admin login failed (${resp.status}): ${txt}`);
  }

  const json = await resp.json();
  _cachedToken    = json.access_token;
  _tokenExpiresAt = now + (json.expires_in ?? 60) * 1000;
  return _cachedToken;
}

// ── Operaciones de usuario ─────────────────────────────────────────────────────

/** Busca un usuario KC por username exacto. Devuelve null si no existe. */
export async function kcFindUser(username) {
  const token = await getAdminToken();
  const resp  = await fetch(
    `${KC_BASE}/admin/realms/${KC_REALM}/users?username=${encodeURIComponent(username)}&exact=true`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (!resp.ok) throw new Error(`KC find user failed: ${resp.status}`);
  const list = await resp.json();
  return list[0] ?? null;
}

/** Busca un usuario KC por email exacto. Devuelve null si no existe. */
export async function kcFindUserByEmail(email) {
  const token = await getAdminToken();
  const resp  = await fetch(
    `${KC_BASE}/admin/realms/${KC_REALM}/users?email=${encodeURIComponent(email)}&exact=true`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (!resp.ok) throw new Error(`KC find user by email failed: ${resp.status}`);
  const list = await resp.json();
  return list[0] ?? null;
}

/** Busca un usuario KC por UUID. Devuelve null si no existe. */
export async function kcGetUserById(kcUserId) {
  const token = await getAdminToken();
  const resp  = await fetch(
    `${KC_BASE}/admin/realms/${KC_REALM}/users/${encodeURIComponent(kcUserId)}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (resp.status === 404) return null;
  if (!resp.ok) throw new Error(`KC get user by id failed: ${resp.status}`);
  return resp.json();
}

/** Crea un usuario KC. Devuelve el UUID asignado por KC. */
export async function kcCreateUser({ username, firstName, lastName, email, socRoleId }) {
  const token = await getAdminToken();

  const body = {
    username,
    firstName: firstName ?? "",
    lastName:  lastName  ?? "",
    enabled:   true,
    emailVerified: !!email,
  };
  if (email) body.email = email;

  const resp = await fetch(`${KC_BASE}/admin/realms/${KC_REALM}/users`, {
    method:  "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  if (!resp.ok) {
    const txt = await resp.text().catch(() => resp.status);
    throw new Error(`KC create user failed (${resp.status}): ${txt}`);
  }

  // KC responde 201 con Location: .../users/{id}
  const location = resp.headers.get("Location") ?? "";
  const kcUserId = location.split("/").pop();
  if (!kcUserId) throw new Error("KC no devolvió ID de usuario en Location");

  // Asignar realm role (analyst / manager / admin) según el rol SOC
  if (socRoleId) {
    await kcAssignRealmRole(kcUserId, socRoleId).catch(() => {});
  }

  return kcUserId;
}

/** Establece / resetea la contraseña de un usuario KC. */
export async function kcSetPassword(kcUserId, password, temporary = false) {
  const token = await getAdminToken();
  const resp  = await fetch(
    `${KC_BASE}/admin/realms/${KC_REALM}/users/${kcUserId}/reset-password`,
    {
      method:  "PUT",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body:    JSON.stringify({ type: "password", value: password, temporary }),
    },
  );
  if (!resp.ok) {
    let detail = "";
    try {
      const body = await resp.json();
      detail = body.errorMessage ?? body.error ?? JSON.stringify(body);
    } catch {
      detail = await resp.text().catch(() => String(resp.status));
    }
    throw new Error(`KC set password failed (${resp.status}): ${detail}`);
  }
}

/** Habilita o deshabilita un usuario KC. */
export async function kcSetUserEnabled(kcUserId, enabled) {
  const token = await getAdminToken();
  const resp  = await fetch(`${KC_BASE}/admin/realms/${KC_REALM}/users/${kcUserId}`, {
    method:  "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body:    JSON.stringify({ enabled }),
  });
  if (!resp.ok) throw new Error(`KC set user enabled failed: ${resp.status}`);
}

/** Asigna el realm role KC (analyst/manager/admin) correspondiente al rol SOC. */
export async function kcAssignRealmRole(kcUserId, socRoleId) {
  const kcRoleName = KC_ROLE_MAP[socRoleId] ?? "analyst";
  const token      = await getAdminToken();

  // Buscar el objeto role por nombre
  const rolesResp  = await fetch(
    `${KC_BASE}/admin/realms/${KC_REALM}/roles/${encodeURIComponent(kcRoleName)}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (!rolesResp.ok) return; // rol no existe, saltear

  const role     = await rolesResp.json();
  const mapResp  = await fetch(
    `${KC_BASE}/admin/realms/${KC_REALM}/users/${kcUserId}/role-mappings/realm`,
    {
      method:  "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body:    JSON.stringify([{ id: role.id, name: role.name }]),
    },
  );
  if (!mapResp.ok) {
    const txt = await mapResp.text().catch(() => mapResp.status);
    throw new Error(`KC assign role failed (${mapResp.status}): ${txt}`);
  }
}

/** Devuelve true si Keycloak está alcanzable. */
export async function kcHealthCheck() {
  try {
    const resp = await fetch(`${KC_BASE}/realms/${KC_REALM}`, { signal: AbortSignal.timeout(3000) });
    return resp.ok;
  } catch {
    return false;
  }
}
