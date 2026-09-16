# Acervo de Ex-Alunos FMABC

Portal estático do acervo de turmas do Centro Universitário FMABC, com backend no Cloudflare Workers + D1 + R2.

## Estrutura

- `index.html` — portal e painel administrativo.
- `worker.js` — código do Cloudflare Worker `fmabc-acervo-api`.

## Publicação do portal

O `index.html` pode ser publicado como site estático pelo GitHub Pages.

O portal usa a API pública do Worker:

`https://fmabc-acervo-api.armredessociais.workers.dev`

## Segurança

Nenhuma senha administrativa, `ADMIN_PASSWORD`, `MIGRATION_KEY` ou chave secreta do Worker deve ser colocada neste repositório.

Os segredos permanecem configurados em **Cloudflare Workers > Settings > Variables and Secrets**.

O login do painel administrativo é feito pelo endpoint do Worker e a sessão usa um token temporário armazenado no navegador.

## Backend Cloudflare

Bindings esperados no Worker:

- `DB` → D1 `fmabc-acervo`
- `BUCKET` → R2 `fmabc-acervo`

Secrets esperados:

- `ADMIN_PASSWORD`
- `MIGRATION_KEY`

## Observação

O frontend não depende do SDK do Supabase e não contém a URL/chave do projeto Supabase. Os dados operacionais do portal são obtidos do Cloudflare D1/R2 por meio do Worker.
