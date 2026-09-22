const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Vary": "Origin",
};

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cache-Control": "no-store",
};

const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_MAX_MS = 8 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 600000;
const PBKDF2_HASH = "SHA-256";
const PBKDF2_LENGTH_BITS = 256;
const RATE_WINDOW_MS = 60 * 1000;
const rateBuckets = new Map();
let adminSessionsSchemaReady = null;

const PUBLIC_CONFIG_KEYS = new Set([
  "background_config",
  "fale_conosco",
  "fotos_galeria",
  "hero_images",
  "portal_pages",
  "site_footer",
  "site_menu",
  "social_banner",
  "timeline_events",
  "turmas_order",
]);

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...SECURITY_HEADERS,
      ...CORS_HEADERS,
      ...extraHeaders,
    },
  });
}

function base64urlFromBytes(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function bytesFromText(text) {
  return new TextEncoder().encode(text);
}

function bytesFromBase64url(value) {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "===".slice((normalized.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", bytesFromText(text));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function safeEqualBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function hashPassword(password) {
  const normalized = String(password ?? "");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", bytesFromText(normalized), { name: "PBKDF2" }, false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
    key,
    PBKDF2_LENGTH_BITS
  );
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${base64urlFromBytes(salt)}$${base64urlFromBytes(new Uint8Array(derived))}`;
}

async function verifyPbkdf2Password(password, encoded) {
  const parts = String(encoded || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1200000) return false;
  let salt, expected;
  try {
    salt = bytesFromBase64url(parts[2]);
    expected = bytesFromBase64url(parts[3]);
  } catch {
    return false;
  }
  if (salt.length < 16 || expected.length !== 32) return false;
  const key = await crypto.subtle.importKey("raw", bytesFromText(String(password ?? "")), { name: "PBKDF2" }, false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: PBKDF2_HASH },
    key,
    PBKDF2_LENGTH_BITS
  );
  return safeEqualBytes(new Uint8Array(derived), expected);
}

async function verifyLegacySha256Password(password, storedHash) {
  if (!String(storedHash || "").startsWith("sha256:")) return false;
  const candidate = await sha256Hex(password);
  return safeEqualBytes(bytesFromHex(candidate), bytesFromHex(String(storedHash).slice(7)));
}

function bytesFromHex(value) {
  const hex = String(value || "").trim();
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function getAllowedOrigins(env) {
  const configured = String(env.ALLOWED_ORIGINS || "").split(",").map(v => v.trim()).filter(Boolean);
  if (configured.length) return new Set(configured);
  // Fallback para o GitHub Pages atualmente utilizado pelo projeto.
  return new Set(["https://regianemeira.github.io"]);
}

function isAllowedBrowserOrigin(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  return getAllowedOrigins(env).has(origin);
}

function getClientIp(request) {
  return String(request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown").split(",")[0].trim();
}

function localRateLimit(key, limit, windowMs = RATE_WINDOW_MS) {
  const now = Date.now();
  const current = rateBuckets.get(key);
  if (!current || now - current.startedAt >= windowMs) {
    rateBuckets.set(key, { startedAt: now, count: 1 });
    if (rateBuckets.size > 5000) {
      for (const [k, v] of rateBuckets) {
        if (now - v.startedAt >= windowMs) rateBuckets.delete(k);
      }
    }
    return { allowed: true, retryAfter: Math.ceil(windowMs / 1000) };
  }
  current.count += 1;
  const remaining = Math.max(0, windowMs - (now - current.startedAt));
  return { allowed: current.count <= limit, retryAfter: Math.ceil(remaining / 1000) };
}

async function enforceRateLimit(request, env, bindingName, key, fallbackLimit) {
  try {
    const binding = env?.[bindingName];
    if (binding && typeof binding.limit === "function") {
      const { success } = await binding.limit({ key });
      return { allowed: !!success, retryAfter: 60 };
    }
  } catch (error) {
    console.warn(`Rate limiter ${bindingName} indisponível; usando fallback local.`, error?.message || error);
  }
  return localRateLimit(`${bindingName}:${key}`, fallbackLimit);
}

async function createSessionToken() {
  return base64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)));
}

async function createSession(request, env, user) {
  await ensureAdminSessionsSchema(env);
  const token = await createSessionToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  const expiresAt = new Date(now + SESSION_MAX_MS).toISOString();
  const id = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO admin_sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at, revoked_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, NULL)
  `).bind(id, user.id, tokenHash, expiresAt).run();
  return token;
}

async function revokeSession(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return;
  const token = header.slice(7).trim();
  if (!token) return;
  const tokenHash = await sha256Hex(token);
  await ensureAdminSessionsSchema(env);
  await env.DB.prepare(`UPDATE admin_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND revoked_at IS NULL`).bind(tokenHash).run();
}

async function verifySession(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  if (!token || token.length < 40 || token.length > 200) return null;

  try {
    await ensureAdminSessionsSchema(env);
    const tokenHash = await sha256Hex(token);
    const session = await env.DB.prepare(`
      SELECT s.id AS session_id, s.user_id, s.created_at, s.last_seen_at, s.expires_at,
             u.id, u.nome, u.email
      FROM admin_sessions s
      JOIN usuarios_admin u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.revoked_at IS NULL
      LIMIT 1
    `).bind(tokenHash).first();
    if (!session) return null;

    const now = Date.now();
    const lastSeen = Date.parse(String(session.last_seen_at || "" ).replace(" ", "T") + "Z");
    const expires = Date.parse(String(session.expires_at || ""));
    if (!Number.isFinite(lastSeen) || !Number.isFinite(expires) || now > expires || now - lastSeen > SESSION_IDLE_MS) {
      await env.DB.prepare(`UPDATE admin_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(session.session_id).run();
      return null;
    }

    await env.DB.prepare(`UPDATE admin_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(session.session_id).run();
    return { id: session.id, nome: session.nome, email: session.email, session_id: session.session_id };
  } catch {
    return null;
  }
}

function requireAdmin(request, env) {
  return verifySession(request, env);
}

async function ensureAdminSessionsSchema(env) {
  if (adminSessionsSchemaReady) return adminSessionsSchemaReady;
  adminSessionsSchemaReady = (async () => {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL,
        revoked_at TEXT DEFAULT NULL
      )
    `).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_admin_sessions_token_hash ON admin_sessions(token_hash)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions(user_id)`).run();
  })();
  try {
    await adminSessionsSchemaReady;
  } catch (error) {
    adminSessionsSchemaReady = null;
    throw error;
  }
}

function parseJson(value, fallback = []) {
  if (Array.isArray(value)) return value;
  try { return value ? JSON.parse(value) : fallback; } catch { return fallback; }
}

async function ensureDepoimentosSchema(env) {
  try {
    const info = await env.DB.prepare(`PRAGMA table_info(depoimentos)`).all();
    const cols = (info?.results || []).map(r => r.name);
    if (!cols.includes('aprovado')) {
      await env.DB.prepare(`ALTER TABLE depoimentos ADD COLUMN aprovado INTEGER NOT NULL DEFAULT 0`).run();
    }
  } catch (error) {
    // A falha de preparação do schema não deve ocultar o erro real da rota.
    console.error('Erro ao preparar schema de depoimentos:', error);
  }
}

async function appendApprovedDepoimentos(env, turma) {
  if (!turma) return turma;
  await ensureDepoimentosSchema(env);
  const embedded = parseJson(turma.depoimentos, []);
  const { results = [] } = await env.DB.prepare(`
    SELECT id, turma_id, autor, texto, created_at
    FROM depoimentos
    WHERE turma_id = ? AND aprovado = 1
    ORDER BY datetime(created_at) ASC, id ASC
  `).bind(turma.id).all();

  const existingKeys = new Set(embedded.map(d => `${String(d.autor || '')}\n${String(d.texto || '')}`));
  const merged = [...embedded];
  for (const item of results) {
    const key = `${String(item.autor || '')}\n${String(item.texto || '')}`;
    if (!existingKeys.has(key)) {
      merged.push({ id: item.id, autor: item.autor, texto: item.texto, created_at: item.created_at });
      existingKeys.add(key);
    }
  }
  turma.depoimentos = merged;
  return turma;
}

async function createPublicDepoimento(request, env) {
  const rate = await enforceRateLimit(request, env, "DEPOIMENTO_RATE_LIMITER", `depoimento:${getClientIp(request)}`, 5);
  if (!rate.allowed) return json({ error: 'Muitas solicitações. Tente novamente em alguns instantes.' }, 429, { 'Retry-After': String(rate.retryAfter) });
  await ensureDepoimentosSchema(env);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido.' }, 400); }

  const turmaId = String(body?.turma_id || '').trim();
  const autor = String(body?.autor || '').trim();
  const texto = String(body?.texto || '').trim();

  if (!turmaId || !autor || !texto) return json({ error: 'Nome, turma e depoimento são obrigatórios.' }, 400);
  if (autor.length > 160) return json({ error: 'O nome informado é muito longo.' }, 400);
  if (texto.length > 300) return json({ error: 'O depoimento deve ter no máximo 300 caracteres.' }, 400);

  const turma = await env.DB.prepare(`SELECT id FROM turmas WHERE id = ? LIMIT 1`).bind(turmaId).first();
  if (!turma) return json({ error: 'Turma não encontrada.' }, 404);

  const id = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO depoimentos (id, turma_id, autor, texto, aprovado, created_at)
    VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
  `).bind(id, turmaId, autor, texto).run();

  return json({ ok: true, id, status: 'pendente' }, 201);
}

async function listPendingDepoimentos(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'Não autorizado.' }, 401);
  await ensureDepoimentosSchema(env);
  const url = new URL(request.url);
  const turmaId = String(url.searchParams.get('turma_id') || '').trim();

  if (turmaId) {
    const { results = [] } = await env.DB.prepare(`
      SELECT id, turma_id, autor, texto, created_at
      FROM depoimentos
      WHERE turma_id = ? AND aprovado = 0
      ORDER BY datetime(created_at) ASC, id ASC
    `).bind(turmaId).all();
    return json(results);
  }

  const { results = [] } = await env.DB.prepare(`
    SELECT id, turma_id, autor, texto, created_at
    FROM depoimentos
    WHERE aprovado = 0
    ORDER BY datetime(created_at) ASC, id ASC
  `).all();
  return json(results);
}

async function approveDepoimento(request, env, id) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'Não autorizado.' }, 401);
  await ensureDepoimentosSchema(env);

  const existente = await env.DB.prepare(`SELECT id FROM depoimentos WHERE id = ? LIMIT 1`).bind(id).first();
  if (!existente) return json({ error: 'Depoimento não encontrado.' }, 404);

  await env.DB.prepare(`UPDATE depoimentos SET aprovado = 1 WHERE id = ?`).bind(id).run();
  return json({ ok: true, id, aprovado: true });
}



async function ensureContatosSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS contatos (
      id TEXT PRIMARY KEY,
      protocolo TEXT NOT NULL UNIQUE,
      nome TEXT NOT NULL,
      email TEXT NOT NULL,
      telefone TEXT,
      curso TEXT,
      turma TEXT,
      assunto TEXT NOT NULL,
      mensagem TEXT NOT NULL,
      consentimento_lgpd INTEGER NOT NULL DEFAULT 0,
      politica_versao TEXT,
      status TEXT NOT NULL DEFAULT 'novo',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

function gerarProtocoloContato() {
  const agora = new Date();
  const data = agora.toISOString().slice(0,10).replace(/-/g,'');
  const sufixo = crypto.randomUUID().replace(/-/g,'').slice(0,8).toUpperCase();
  return `FMABC-${data}-${sufixo}`;
}

async function createPublicContato(request, env) {
  const rate = await enforceRateLimit(request, env, "CONTACT_RATE_LIMITER", `contact:${getClientIp(request)}`, 5);
  if (!rate.allowed) return json({ error: 'Muitas solicitações. Tente novamente em alguns instantes.' }, 429, { 'Retry-After': String(rate.retryAfter) });
  await ensureContatosSchema(env);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido.' }, 400); }
  if (String(body?.honeypot || '').trim()) return json({ ok: true, protocol: 'Recebido' }, 201);

  const nome = String(body?.nome || '').trim();
  const email = String(body?.email || '').trim().toLowerCase();
  const telefone = String(body?.telefone || '').trim();
  const curso = String(body?.curso || '').trim();
  const turma = String(body?.turma || '').trim();
  const assunto = String(body?.assunto || '').trim();
  const mensagem = String(body?.mensagem || '').trim();
  const consent = Boolean(body?.consentimento_lgpd);
  const versao = String(body?.politica_versao || '').trim();

  if (!nome || !email || !assunto || !mensagem) return json({ error: 'Preencha os campos obrigatórios.' }, 400);
  if (!consent) return json({ error: 'É necessário aceitar a Política de Privacidade.' }, 400);
  if (nome.length > 160 || email.length > 180 || telefone.length > 30 || curso.length > 140 || turma.length > 80 || assunto.length > 120 || mensagem.length > 4000) {
    return json({ error: 'Um ou mais campos ultrapassam o limite permitido.' }, 400);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Informe um e-mail válido.' }, 400);

  const id = crypto.randomUUID();
  const protocolo = gerarProtocoloContato();
  await env.DB.prepare(`
    INSERT INTO contatos (
      id, protocolo, nome, email, telefone, curso, turma, assunto, mensagem,
      consentimento_lgpd, politica_versao, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'novo', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `).bind(id, protocolo, nome, email, telefone, curso, turma, assunto, mensagem, 1, versao || '1.0').run();

  return json({ ok: true, id, protocol: protocolo, status: 'novo' }, 201);
}

async function listAdminContatos(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'Não autorizado.' }, 401);
  await ensureContatosSchema(env);
  const { results = [] } = await env.DB.prepare(`
    SELECT id, protocolo, nome, email, telefone, curso, turma, assunto, mensagem,
           consentimento_lgpd, politica_versao, status, created_at, updated_at
    FROM contatos
    ORDER BY datetime(created_at) DESC, id DESC
    LIMIT 200
  `).all();
  return json(results);
}

async function updateAdminContatoStatus(request, env, id) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'Não autorizado.' }, 401);
  await ensureContatosSchema(env);
  let body; try { body = await request.json(); } catch { return json({ error: 'JSON inválido.' }, 400); }
  const status = String(body?.status || '').trim();
  const permitidos = new Set(['novo','em_atendimento','respondido','arquivado']);
  if (!permitidos.has(status)) return json({ error: 'Status inválido.' }, 400);
  const result = await env.DB.prepare(`UPDATE contatos SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(status, id).run();
  if (!result?.meta?.changes) return json({ error: 'Contato não encontrado.' }, 404);
  return json({ ok: true, id, status });
}

function mapTurma(row, requestUrl) {
  const galeria = parseJson(row.galeria, []);
  const depoimentos = parseJson(row.depoimentos, []);
  const formandos = parseJson(row.formandos, []);

  return {
    id: row.id,
    curso: row.curso,
    titulo: row.titulo || row.nome || "",
    nome: row.nome || row.titulo || "",
    ano: row.ano || "",
    qtdFormandos: row.qtd_formandos || "",
    cardDesc: row.card_desc || "",
    resumo: row.card_desc || "",
    img: row.img || "",
    paraninfo: row.paraninfo || "",
    patrono: row.patrono || "",
    historia: row.historia || "",
    galeria,
    depoimentos,
    formandos,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function sanitizeFolder(folder) {
  const raw = String(folder || "turmas").replace(/\\/g, "/");
  const parts = raw.split("/").map(p => p.trim()).filter(Boolean);
  if (!parts.length) return "turmas";
  if (parts.some(p => p === "." || p === ".." || /[^a-zA-Z0-9._-]/.test(p))) {
    throw new Error("Pasta inválida.");
  }
  return parts.join("/");
}

function extensionFromType(contentType, fallbackName = "") {
  const type = String(contentType || "").toLowerCase();
  if (type.includes("jpeg") || type.includes("jpg")) return "jpg";
  if (type.includes("png")) return "png";
  if (type.includes("webp")) return "webp";
  if (type.includes("gif")) return "gif";
  if (type.includes("svg")) return "svg";
  const match = String(fallbackName).match(/\.([a-z0-9]+)$/i);
  return match ? match[1].toLowerCase() : "bin";
}

function assetUrl(requestUrl, key) {
  const origin = new URL(requestUrl).origin;
  const encodedKey = key.split("/").map(encodeURIComponent).join("/");
  return `${origin}/assets/${encodedKey}`;
}

async function adminLogin(request, env) {
  const ip = getClientIp(request);
  const email = String((await request.clone().json().catch(() => ({})))?.email || "").trim().toLowerCase();
  const rateIp = await enforceRateLimit(request, env, "LOGIN_RATE_LIMITER", `login-ip:${ip}`, 20);
  const rateAccount = await enforceRateLimit(request, env, "LOGIN_RATE_LIMITER", `login-account:${email}`, 5);
  if (!rateIp.allowed || !rateAccount.allowed) {
    const retryAfter = Math.max(rateIp.retryAfter || 60, rateAccount.retryAfter || 60);
    return json({ error: "Muitas tentativas de login. Tente novamente em alguns instantes." }, 429, { "Retry-After": String(retryAfter) });
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: "JSON inválido." }, 400); }

  const loginEmail = String(body?.email || "").trim().toLowerCase();
  const senha = String(body?.senha || "");
  if (!loginEmail || !senha) return json({ error: "Informe e-mail e senha." }, 400);
  if (loginEmail.length > 254 || senha.length > 256) return json({ error: "Usuário ou senha incorretos." }, 401);

  const user = await env.DB.prepare(`
    SELECT id, nome, email, senha
    FROM usuarios_admin
    WHERE lower(email) = ?
    LIMIT 1
  `).bind(loginEmail).first();

  if (!user) return json({ error: "Usuário ou senha incorretos." }, 401);

  let senhaValida = false;
  let needsUpgrade = false;

  if (user.senha && String(user.senha).startsWith("pbkdf2-sha256$")) {
    senhaValida = await verifyPbkdf2Password(senha, user.senha);
  } else if (user.senha && String(user.senha).startsWith("sha256:")) {
    senhaValida = await verifyLegacySha256Password(senha, user.senha);
    needsUpgrade = senhaValida;
  } else if (!user.senha && env.ADMIN_PASSWORD && env.ADMIN_BOOTSTRAP_EMAIL && loginEmail === String(env.ADMIN_BOOTSTRAP_EMAIL).trim().toLowerCase()) {
    // Compatibilidade temporária apenas com a conta de bootstrap explicitamente definida.
    senhaValida = senha === env.ADMIN_PASSWORD;
    needsUpgrade = senhaValida;
  }

  if (!senhaValida) return json({ error: "Usuário ou senha incorretos." }, 401);

  if (needsUpgrade) {
    const upgradedHash = await hashPassword(senha);
    await env.DB.prepare(`UPDATE usuarios_admin SET senha = ? WHERE id = ?`).bind(upgradedHash, user.id).run();
  }

  const token = await createSession(request, env, user);
  return json({
    ok: true,
    token,
    user: { id: user.id, nome: user.nome, email: user.email },
  });
}

async function adminLogout(request, env) {
  try { await revokeSession(request, env); } catch {}
  return json({ ok: true });
}

async function adminHeartbeat(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Sessão expirada." }, 401);
  return json({ ok: true, user: { id: admin.id, nome: admin.nome, email: admin.email } });
}

async function adminUpload(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  const url = new URL(request.url);
  const folder = sanitizeFolder(url.searchParams.get("folder") || "turmas");
  const form = await request.formData();
  const file = form.get("file");

  if (!(file instanceof File)) return json({ error: "Arquivo não informado." }, 400);
  const allowedTypes = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
  if (!allowedTypes.has(String(file.type || "").toLowerCase())) return json({ error: "Formato de imagem não permitido. Use JPG, PNG, WEBP ou GIF." }, 400);
  if (file.size > 6 * 1024 * 1024) return json({ error: "A imagem deve ter no máximo 6 MB." }, 400);
  if (String(file.name || "").length > 180) return json({ error: "Nome de arquivo muito longo." }, 400);

  const ext = extensionFromType(file.type, file.name);
  const key = `${folder}/${Date.now()}-${crypto.randomUUID()}.${ext}`;

  await env.BUCKET.put(key, file.stream(), {
    httpMetadata: {
      contentType: file.type || "application/octet-stream",
      cacheControl: "public, max-age=31536000, immutable",
    },
  });

  return json({
    ok: true,
    key,
    url: assetUrl(request.url, key),
  });
}

async function listAdminUsers(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  const { results } = await env.DB.prepare(`
    SELECT id, nome, email, created_at
    FROM usuarios_admin
    ORDER BY datetime(created_at) DESC, nome COLLATE NOCASE ASC
  `).all();

  return json(results);
}

async function createAdminUser(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ error: "JSON inválido." }, 400); }

  const nome = String(body?.nome || "").trim();
  const email = String(body?.email || "").trim().toLowerCase();
  const senha = String(body?.senha || "");

  if (!nome || !email || !senha) {
    return json({ error: "Nome, e-mail e senha são obrigatórios." }, 400);
  }
  if (senha.length < 12 || senha.length > 256) {
    return json({ error: "A senha deve ter entre 12 e 256 caracteres." }, 400);
  }

  const existente = await env.DB.prepare(`SELECT id FROM usuarios_admin WHERE lower(email) = ? LIMIT 1`).bind(email).first();
  if (existente) return json({ error: "Já existe um administrador com este e-mail." }, 409);

  const id = crypto.randomUUID();
  const senhaHash = await hashPassword(senha);

  await env.DB.prepare(`
    INSERT INTO usuarios_admin (id, nome, email, senha, created_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
  `).bind(id, nome, email, senhaHash).run();

  const row = await env.DB.prepare(`SELECT id, nome, email, created_at FROM usuarios_admin WHERE id = ?`).bind(id).first();
  return json(row, 201);
}

async function deleteAdminUser(request, env, id) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  if (String(admin.id) === String(id)) {
    return json({ error: "Você não pode excluir o usuário administrador da sessão atual." }, 400);
  }

  const existing = await env.DB.prepare(`SELECT id FROM usuarios_admin WHERE id = ? LIMIT 1`).bind(id).first();
  if (!existing) return json({ error: "Administrador não encontrado." }, 404);

  await ensureAdminSessionsSchema(env);
  await env.DB.prepare(`UPDATE admin_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL`).bind(id).run();
  await env.DB.prepare(`DELETE FROM usuarios_admin WHERE id = ?`).bind(id).run();
  return json({ ok: true, id });
}


async function createCourse(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ error: "JSON inválido." }, 400); }

  const nome = String(body?.nome || "").trim();
  const descricao = String(body?.descricao || "").trim();
  if (!nome) return json({ error: "Nome do curso é obrigatório." }, 400);

  const existente = await env.DB.prepare(`SELECT id FROM cursos WHERE lower(nome) = ? LIMIT 1`).bind(nome.toLowerCase()).first();
  if (existente) return json({ error: "Já existe um curso com este nome." }, 409);

  const id = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO cursos (id, nome, descricao, created_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
  `).bind(id, nome, descricao).run();

  const row = await env.DB.prepare(`SELECT id, nome, descricao, created_at FROM cursos WHERE id = ?`).bind(id).first();
  return json(row, 201);
}

async function updateCourse(request, env, id) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ error: "JSON inválido." }, 400); }
  const nome = String(body?.nome || "").trim();
  const descricao = String(body?.descricao || "").trim();
  if (!nome) return json({ error: "Nome do curso é obrigatório." }, 400);

  const existing = await env.DB.prepare(`SELECT id FROM cursos WHERE id = ? LIMIT 1`).bind(id).first();
  if (!existing) return json({ error: "Curso não encontrado." }, 404);

  const dup = await env.DB.prepare(`SELECT id FROM cursos WHERE lower(nome) = ? AND id <> ? LIMIT 1`).bind(nome.toLowerCase(), id).first();
  if (dup) return json({ error: "Já existe outro curso com este nome." }, 409);

  await env.DB.prepare(`UPDATE cursos SET nome = ?, descricao = ? WHERE id = ?`).bind(nome, descricao, id).run();
  const row = await env.DB.prepare(`SELECT id, nome, descricao, created_at FROM cursos WHERE id = ?`).bind(id).first();
  return json(row);
}

async function deleteCourse(request, env, id) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  const existing = await env.DB.prepare(`SELECT id FROM cursos WHERE id = ? LIMIT 1`).bind(id).first();
  if (!existing) return json({ error: "Curso não encontrado." }, 404);

  await env.DB.prepare(`DELETE FROM cursos WHERE id = ?`).bind(id).run();
  return json({ ok: true, id });
}


async function updateSiteConfig(request, env, id) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ error: "JSON inválido." }, 400); }

  const valor = body?.valor ?? null;
  const serialized = typeof valor === "string" ? valor : JSON.stringify(valor);
  if (serialized.length > 2_000_000) return json({ error: "Configuração muito grande para ser salva." }, 413);

  // Garante que a tabela de configurações exista mesmo em ambientes que
  // foram criados antes da adoção do CMS. Não altera dados existentes.
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS site_config (
      id TEXT PRIMARY KEY,
      valor TEXT,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    INSERT INTO site_config (id, valor, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
      valor = excluded.valor,
      updated_at = CURRENT_TIMESTAMP
  `).bind(id, serialized).run();

  const row = await env.DB.prepare(`
    SELECT id, valor, updated_at FROM site_config WHERE id = ? LIMIT 1
  `).bind(id).first();

  let parsed = row?.valor;
  try { parsed = JSON.parse(row.valor); } catch {}
  return json({ ok: true, id: row.id, valor: parsed, updated_at: row.updated_at });
}

function normalizeTurmaBody(body, existing = null) {
  const turma = body || {};
  return {
    curso: String(turma.curso ?? existing?.curso ?? "").trim(),
    titulo: String(turma.titulo ?? turma.nome ?? existing?.titulo ?? existing?.nome ?? "").trim(),
    nome: String(turma.nome ?? turma.titulo ?? existing?.nome ?? existing?.titulo ?? "").trim(),
    ano: String(turma.ano ?? existing?.ano ?? "").trim(),
    qtd_formandos: String(turma.qtdFormandos ?? turma.qtd_formandos ?? existing?.qtd_formandos ?? "").trim(),
    card_desc: String(turma.cardDesc ?? turma.resumo ?? turma.card_desc ?? existing?.card_desc ?? ""),
    img: String(turma.img ?? existing?.img ?? ""),
    paraninfo: String(turma.paraninfo ?? existing?.paraninfo ?? ""),
    patrono: String(turma.patrono ?? existing?.patrono ?? ""),
    historia: String(turma.historia ?? existing?.historia ?? ""),
    galeria: JSON.stringify(Array.isArray(turma.galeria) ? turma.galeria : parseJson(turma.galeria, parseJson(existing?.galeria, []))),
    depoimentos: JSON.stringify(Array.isArray(turma.depoimentos) ? turma.depoimentos : parseJson(turma.depoimentos, parseJson(existing?.depoimentos, []))),
    formandos: JSON.stringify(Array.isArray(turma.formandos) ? turma.formandos : parseJson(turma.formandos, parseJson(existing?.formandos, []))),
  };
}

async function createTurma(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ error: "JSON inválido." }, 400); }

  const values = normalizeTurmaBody(body);
  if (!values.curso || !values.titulo || !values.ano) {
    return json({ error: "Curso, nome da turma e ano são obrigatórios." }, 400);
  }

  const id = body?.id || crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO turmas (
      id, curso, titulo, nome, ano, qtd_formandos, card_desc, img,
      paraninfo, patrono, historia, galeria, depoimentos, formandos, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `).bind(
    id, values.curso, values.titulo, values.nome, values.ano,
    values.qtd_formandos, values.card_desc, values.img,
    values.paraninfo, values.patrono, values.historia,
    values.galeria, values.depoimentos, values.formandos
  ).run();

  const row = await env.DB.prepare(`SELECT * FROM turmas WHERE id = ?`).bind(id).first();
  return json(mapTurma(row, request.url), 201);
}

async function updateTurma(request, env, id) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  const existing = await env.DB.prepare(`SELECT * FROM turmas WHERE id = ?`).bind(id).first();
  if (!existing) return json({ error: "Turma não encontrada." }, 404);

  let body;
  try { body = await request.json(); } catch { return json({ error: "JSON inválido." }, 400); }
  const values = normalizeTurmaBody(body, existing);

  if (!values.curso || !values.titulo || !values.ano) {
    return json({ error: "Curso, nome da turma e ano são obrigatórios." }, 400);
  }

  await env.DB.prepare(`
    UPDATE turmas SET
      curso = ?, titulo = ?, nome = ?, ano = ?, qtd_formandos = ?, card_desc = ?, img = ?,
      paraninfo = ?, patrono = ?, historia = ?, galeria = ?, depoimentos = ?, formandos = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(
    values.curso, values.titulo, values.nome, values.ano, values.qtd_formandos,
    values.card_desc, values.img, values.paraninfo, values.patrono, values.historia,
    values.galeria, values.depoimentos, values.formandos, id
  ).run();

  const row = await env.DB.prepare(`SELECT * FROM turmas WHERE id = ?`).bind(id).first();
  return json(mapTurma(row, request.url));
}

async function deleteTurma(request, env, id) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  const existing = await env.DB.prepare(`SELECT id FROM turmas WHERE id = ?`).bind(id).first();
  if (!existing) return json({ error: "Turma não encontrada." }, 404);

  await env.DB.prepare(`DELETE FROM turmas WHERE id = ?`).bind(id).run();
  return json({ ok: true, id });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (!isAllowedBrowserOrigin(request, env)) {
        return json({ error: "Origem não autorizada." }, 403);
      }

      if (path === "/health" && request.method === "GET") {
        return json({ ok: true });
      }

      if (path === "/api/admin/login" && request.method === "POST") return adminLogin(request, env);
      if (path === "/api/admin/logout" && request.method === "POST") return adminLogout(request, env);
      if (path === "/api/admin/heartbeat" && request.method === "POST") return adminHeartbeat(request, env);

      if (path === "/api/admin/me" && request.method === "GET") {
        const admin = await requireAdmin(request, env);
        if (!admin) return json({ error: "Não autorizado." }, 401);
        return json({ ok: true, user: admin });
      }

      if (path === "/api/admin/upload" && request.method === "POST") return adminUpload(request, env);

      if (path === "/api/admin/usuarios" && request.method === "GET") return listAdminUsers(request, env);
      if (path === "/api/admin/usuarios" && request.method === "POST") return createAdminUser(request, env);
      const adminUserMatch = path.match(/^\/api\/admin\/usuarios\/([^/]+)$/);
      if (adminUserMatch && request.method === "DELETE") return deleteAdminUser(request, env, adminUserMatch[1]);

      if (path === "/admin/migration-status" && request.method === "GET") {
        const header = request.headers.get("Authorization") || "";
        if (!header.startsWith("Bearer ") || header.slice(7) !== env.MIGRATION_KEY) return json({ error: "Não autorizado." }, 401);
        return json({ ok: true, urlsAindaNoSupabase: 0, totalUrlsEncontradas: 0, message: "A migração manual das imagens está em andamento por R2; esta rota permanece apenas para compatibilidade." });
      }

      if (path === "/admin/migrate-images" && request.method === "POST") {
        const header = request.headers.get("Authorization") || "";
        if (!header.startsWith("Bearer ") || header.slice(7) !== env.MIGRATION_KEY) return json({ error: "Não autorizado." }, 401);
        return json({ ok: false, error: "Use o upload manual pelo painel para as imagens de exemplo." }, 400);
      }

      if (path === "/api/turmas" && request.method === "GET") {
        const { results } = await env.DB.prepare(`
          SELECT id, curso, titulo, nome, ano, qtd_formandos, card_desc, img, created_at, updated_at
          FROM turmas
          ORDER BY datetime(created_at) ASC, id ASC
        `).all();
        return json(results.map(row => mapTurma(row, request.url)));
      }

      const adminTurmaMatch = path.match(/^\/api\/admin\/turmas(?:\/([^/]+))?$/);
      if (adminTurmaMatch) {
        const id = adminTurmaMatch[1];
        if (request.method === "POST" && !id) return createTurma(request, env);
        if (request.method === "PUT" && id) return updateTurma(request, env, id);
        if (request.method === "DELETE" && id) return deleteTurma(request, env, id);
      }

      if (path === "/api/depoimentos" && request.method === "POST") return createPublicDepoimento(request, env);
      if (path === "/api/contatos" && request.method === "POST") return createPublicContato(request, env);
      if (path === "/api/admin/contatos" && request.method === "GET") return listAdminContatos(request, env);
      const adminContatoMatch = path.match(/^\/api\/admin\/contatos\/([^/]+)\/status$/);
      if (adminContatoMatch && request.method === "PUT") return updateAdminContatoStatus(request, env, decodeURIComponent(adminContatoMatch[1]));

      if (path === "/api/admin/depoimentos" && request.method === "GET") return listPendingDepoimentos(request, env);
      const adminDepoimentoMatch = path.match(/^\/api\/admin\/depoimentos\/([^/]+)\/aprovar$/);
      if (adminDepoimentoMatch && request.method === "PUT") return approveDepoimento(request, env, decodeURIComponent(adminDepoimentoMatch[1]));

      const turmaMatch = path.match(/^\/api\/turmas\/([^/]+)$/);
      if (turmaMatch && request.method === "GET") {
        const row = await env.DB.prepare(`SELECT * FROM turmas WHERE id = ? LIMIT 1`).bind(turmaMatch[1]).first();
        if (!row) return json({ error: "Turma não encontrada." }, 404);
        const turma = mapTurma(row, request.url);
        await appendApprovedDepoimentos(env, turma);
        return json(turma);
      }

      if (path === "/api/admin/cursos" && request.method === "POST") return createCourse(request, env);
      const adminCourseMatch = path.match(/^\/api\/admin\/cursos\/([^/]+)$/);
      if (adminCourseMatch && request.method === "PUT") return updateCourse(request, env, decodeURIComponent(adminCourseMatch[1]));
      if (adminCourseMatch && request.method === "DELETE") return deleteCourse(request, env, decodeURIComponent(adminCourseMatch[1]));

      if (path === "/api/cursos" && request.method === "GET") {
        const { results } = await env.DB.prepare(`SELECT id, nome, descricao, created_at FROM cursos ORDER BY nome COLLATE NOCASE ASC`).all();
        return json(results);
      }

      const adminConfigMatch = path.match(/^\/api\/admin\/config\/([^/]+)$/);
      if (adminConfigMatch && request.method === "PUT") {
        return updateSiteConfig(request, env, decodeURIComponent(adminConfigMatch[1]));
      }

      const configMatch = path.match(/^\/api\/config\/([^/]+)$/);
      if (configMatch && request.method === "GET") {
        const configId = decodeURIComponent(configMatch[1]);
        if (!PUBLIC_CONFIG_KEYS.has(configId)) return json({ error: "Configuração não encontrada." }, 404);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS site_config (
            id TEXT PRIMARY KEY,
            valor TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `).run();
        const row = await env.DB.prepare(`SELECT id, valor, updated_at FROM site_config WHERE id = ? LIMIT 1`).bind(configMatch[1]).first();
        if (!row) return json({ error: "Configuração não encontrada." }, 404);
        let valor = row.valor;
        try { valor = JSON.parse(row.valor); } catch {}
        return json({ ok: true, id: row.id, valor, updated_at: row.updated_at });
      }

      if (path.startsWith("/assets/") && request.method === "GET") {
        const key = decodeURIComponent(path.slice("/assets/".length));
        if (!key) return new Response("Not Found", { status: 404, headers: CORS_HEADERS });
        const object = await env.BUCKET.get(key);
        if (!object) return new Response("Arquivo não encontrado.", { status: 404, headers: CORS_HEADERS });
        const headers = new Headers(CORS_HEADERS);
        object.writeHttpMetadata(headers);
        headers.set("etag", object.httpEtag);
        headers.set("Cache-Control", "public, max-age=31536000, immutable");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        return new Response(object.body, { status: 200, headers });
      }

      return json({
        error: "Rota não encontrada.",
      }, 404);
    } catch (error) {
      console.error("Worker error:", error);
      return json({ error: "Erro interno do Worker." }, 500);
    }
  },
};
