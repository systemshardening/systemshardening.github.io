# systemshardening.github.io

Static site for [systemshardening.com](https://systemshardening.github.io) — hardening real systems in production.

## Architecture

Content lives in a private repo (`systemshardening-roadmap-planning`). This site repo pulls articles at build time via GitHub Actions. No content is stored in this repo.

## Local Development

Clone this repo and the content repo side by side:

```bash
git clone git@github.com:systemshardening/systemshardening.github.io.git
git clone git@github.com:systemshardening/systemshardening-roadmap-planning.git
```

Run the dev server:

```bash
cd systemshardening.github.io
npm install
CONTENT_DIR=../systemshardening-roadmap-planning/articles npm run dev
```

Site is available at `http://localhost:8080`.

## Deployment

Automatic via GitHub Actions on push to `main` or when content is updated in the private repo.

Requires `CONTENT_REPO_READ_TOKEN` secret — a fine-grained PAT with read access to `systemshardening-roadmap-planning`.

## Stack

- **Eleventy** — static site generator
- **Nunjucks** — templating
- **GitHub Pages** — hosting
- **GitHub Actions** — build and deploy
