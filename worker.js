const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
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

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", bytesFromText(text));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.startsWith("sha256:")) return false;
  return (await sha256Hex(password)) === storedHash.slice(7);
}

async function hmacSha256(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    bytesFromText(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, bytesFromText(message));
  return base64urlFromBytes(new Uint8Array(sig));
}

async function createSessionToken(email, name, secret) {
  const payload = {
    email,
    name,
    exp: Date.now() + 12 * 60 * 60 * 1000,
    nonce: crypto.randomUUID(),
  };
  const encoded = base64urlFromBytes(bytesFromText(JSON.stringify(payload)));
  const sig = await hmacSha256(secret, encoded);
  return `${encoded}.${sig}`;
}

function textFromBase64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function verifySession(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  if (!env.ADMIN_PASSWORD) return null;

  const token = header.slice(7).trim();
  const dot = token.indexOf(".");
  if (dot <= 0) return null;

  const encoded = token.slice(0, dot);
  const signature = token.slice(dot + 1);

  try {
    const expected = await hmacSha256(env.ADMIN_PASSWORD, encoded);
    if (signature !== expected) return null;

    const payload = JSON.parse(textFromBase64url(encoded));
    if (!payload?.email || !payload?.exp || Date.now() > Number(payload.exp)) return null;

    const user = await env.DB.prepare(`
      SELECT id, nome, email
      FROM usuarios_admin
      WHERE email = ?
      LIMIT 1
    `).bind(payload.email).first();

    if (!user) return null;
    return user;
  } catch {
    return null;
  }
}

function requireAdmin(request, env) {
  return verifySession(request, env);
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
    if (!cols.includes('lgpd_aceito')) {
      await env.DB.prepare(`ALTER TABLE depoimentos ADD COLUMN lgpd_aceito INTEGER NOT NULL DEFAULT 0`).run();
    }
    if (!cols.includes('lgpd_aceito_em')) {
      await env.DB.prepare(`ALTER TABLE depoimentos ADD COLUMN lgpd_aceito_em TEXT`).run();
    }
    if (!cols.includes('politica_versao')) {
      await env.DB.prepare(`ALTER TABLE depoimentos ADD COLUMN politica_versao TEXT`).run();
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
  await ensureDepoimentosSchema(env);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'JSON inválido.' }, 400); }

  const turmaId = String(body?.turma_id || '').trim();
  const autor = String(body?.autor || '').trim();
  const texto = String(body?.texto || '').trim();
  const lgpdAceito = body?.lgpd_aceito === true;
  const politicaVersao = String(body?.politica_versao || '1.0').trim().slice(0, 20) || '1.0';

  if (!turmaId || !autor || !texto) return json({ error: 'Nome, turma e depoimento são obrigatórios.' }, 400);
  if (!lgpdAceito) return json({ error: 'É necessário aceitar a Política de Privacidade para enviar o depoimento.' }, 400);
  if (autor.length > 160) return json({ error: 'O nome informado é muito longo.' }, 400);
  if (texto.length > 300) return json({ error: 'O depoimento deve ter no máximo 300 caracteres.' }, 400);

  const turma = await env.DB.prepare(`SELECT id FROM turmas WHERE id = ? LIMIT 1`).bind(turmaId).first();
  if (!turma) return json({ error: 'Turma não encontrada.' }, 404);

  const id = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO depoimentos (id, turma_id, autor, texto, aprovado, lgpd_aceito, lgpd_aceito_em, politica_versao, created_at)
    VALUES (?, ?, ?, ?, 0, 1, ?, ?, CURRENT_TIMESTAMP)
  `).bind(id, turmaId, autor, texto, new Date().toISOString(), politicaVersao).run();

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
      SELECT id, turma_id, autor, texto, lgpd_aceito, lgpd_aceito_em, politica_versao, created_at
      FROM depoimentos
      WHERE turma_id = ? AND aprovado = 0
      ORDER BY datetime(created_at) ASC, id ASC
    `).bind(turmaId).all();
    return json(results);
  }

  const { results = [] } = await env.DB.prepare(`
    SELECT id, turma_id, autor, texto, lgpd_aceito, lgpd_aceito_em, politica_versao, created_at
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
  if (!env.ADMIN_PASSWORD) {
    return json({ error: "ADMIN_PASSWORD não configurada no Worker." }, 500);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: "JSON inválido." }, 400); }

  const email = String(body?.email || "").trim().toLowerCase();
  const senha = String(body?.senha || "");

  if (!email || !senha) return json({ error: "Informe e-mail e senha." }, 400);

  const user = await env.DB.prepare(`
    SELECT id, nome, email
    FROM usuarios_admin
    WHERE lower(email) = ?
    LIMIT 1
  `).bind(email).first();

  if (!user) {
    return json({ error: "Usuário ou senha incorretos." }, 401);
  }

  // Compatibilidade com o administrador principal atual, autenticado pelo secret do Worker.
  let senhaValida = senha === env.ADMIN_PASSWORD;

  // Novos administradores podem usar senha própria, armazenada apenas como hash SHA-256 no D1.
  if (!senhaValida && user.senha) {
    senhaValida = await verifyPassword(senha, user.senha);
  }

  if (!senhaValida) {
    return json({ error: "Usuário ou senha incorretos." }, 401);
  }

  const token = await createSessionToken(user.email, user.nome, env.ADMIN_PASSWORD);
  return json({
    ok: true,
    token,
    user: {
      id: user.id,
      nome: user.nome,
      email: user.email,
    },
  });
}

async function adminUpload(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Não autorizado." }, 401);

  const url = new URL(request.url);
  const folder = sanitizeFolder(url.searchParams.get("folder") || "turmas");
  const form = await request.formData();
  const file = form.get("file");

  if (!(file instanceof File)) return json({ error: "Arquivo não informado." }, 400);
  if (!String(file.type || "").startsWith("image/")) return json({ error: "O arquivo precisa ser uma imagem." }, 400);
  if (file.size > 6 * 1024 * 1024) return json({ error: "A imagem deve ter no máximo 6 MB." }, 400);

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
  if (senha.length < 6) {
    return json({ error: "A senha deve ter pelo menos 6 caracteres." }, 400);
  }

  const existente = await env.DB.prepare(`SELECT id FROM usuarios_admin WHERE lower(email) = ? LIMIT 1`).bind(email).first();
  if (existente) return json({ error: "Já existe um administrador com este e-mail." }, 409);

  const id = crypto.randomUUID();
  const senhaHash = `sha256:${await sha256Hex(senha)}`;

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
  return json({ id: row.id, valor: parsed, updated_at: row.updated_at });
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
      if (path === "/health" && request.method === "GET") {
        const db = await env.DB.prepare("SELECT 1 AS ok").first();
        return json({ ok: true, worker: "fmabc-acervo-api", d1: db?.ok === 1, r2: !!env.BUCKET, adminPasswordConfigured: !!env.ADMIN_PASSWORD });
      }

      if (path === "/api/admin/login" && request.method === "POST") return adminLogin(request, env);

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
        const row = await env.DB.prepare(`SELECT id, valor, updated_at FROM site_config WHERE id = ? LIMIT 1`).bind(configMatch[1]).first();
        if (!row) return json({ error: "Configuração não encontrada." }, 404);
        let valor = row.valor;
        try { valor = JSON.parse(row.valor); } catch {}
        return json({ id: row.id, valor, updated_at: row.updated_at });
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
        return new Response(object.body, { status: 200, headers });
      }

      return json({
        error: "Rota não encontrada.",
        routes: [
          "GET /health",
          "POST /api/admin/login",
          "GET /api/admin/me",
          "POST /api/admin/upload?folder=...",
          "GET /api/admin/usuarios",
          "POST /api/admin/usuarios",
          "DELETE /api/admin/usuarios/:id",
          "GET /api/turmas",
          "GET /api/turmas/:id",
          "POST /api/admin/turmas",
          "PUT /api/admin/turmas/:id",
          "DELETE /api/admin/turmas/:id",
          "POST /api/depoimentos",
          "GET /api/admin/depoimentos?turma_id=...",
          "PUT /api/admin/depoimentos/:id/aprovar",
          "GET /api/cursos",
          "POST /api/admin/cursos",
          "PUT /api/admin/cursos/:id",
          "DELETE /api/admin/cursos/:id",
          "GET /api/config/:id",
          "GET /assets/*",
        ],
      }, 404);
    } catch (error) {
      console.error("Worker error:", error);
      return json({ error: "Erro interno do Worker.", message: error?.message || String(error) }, 500);
    }
  },
};
