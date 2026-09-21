# FMABC Acervo — Portal de Memória

Arquivos principais do portal publicado no GitHub Pages:

- `index.html` — página inicial e Área Administrativa.
- `linha-do-tempo.html` — página institucional editável pelo CMS.
- `depoimentos-ex-alunos.html` — página institucional editável, mantendo o formulário de depoimentos.
- `galeria-diretores-reitores.html` — página institucional editável pelo CMS.
- `professores-emeritos.html` — página institucional editável pelo CMS.
- `pagina.html` — modelo para novas páginas personalizadas.
- `worker.js` — Cloudflare Worker/API (não precisa ser alterado para esta atualização).

## Gestão de Páginas

As quatro páginas institucionais já existentes também são administráveis no menu **Gestão de Páginas**. É possível editar título, resumo, conteúdo, conteúdo complementar, informações adicionais, banner, SEO, visibilidade e presença no menu.

O conteúdo editado dessas páginas é salvo no Cloudflare D1 na configuração `portal_pages`. Os arquivos HTML institucionais consultam essa configuração quando publicados, sem perder as funções específicas de cada página.

A criação de páginas novas continua usando `pagina.html?slug=...` e os registros personalizados também ficam em `portal_pages`.
