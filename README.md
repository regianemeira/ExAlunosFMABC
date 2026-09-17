# Portal de Memória FMABC — páginas independentes

A página inicial permanece em `index.html`. Os tópicos do menu de memória agora são páginas separadas:

- `linha-do-tempo.html`
- `depoimentos-ex-alunos.html`
- `galeria-diretores-reitores.html`
- `professores-emeritos.html`

A página inicial não exibe mais essas quatro seções como blocos de conteúdo. O menu continua sendo carregado do Cloudflare D1 pela configuração `site_menu`. Links antigos salvos como `#linha-do-tempo`, `#depoimentos-ex-alunos`, `#galeria-diretores-reitores` e `#professores-emeritos` são migrados automaticamente para os arquivos correspondentes durante a leitura.

Os links internos usam caminhos relativos para funcionar no GitHub Pages, inclusive quando o repositório é publicado em uma subpasta.

API: https://fmabc-acervo-api.armredessociais.workers.dev
