# portal

Vue 3 + Vite. Requires node >= 22.18 (CI uses node 24 LTS).

## Project setup
```
yarn install
```

### Dev server with hot reload (localhost / dev / staging / prod API)
```
yarn serve-local
yarn serve-dev
yarn serve-staging
yarn serve-prod
```

### Production build (output in dist/)
```
yarn build-local
yarn build-dev
yarn build-staging
yarn build-prod
```

### Lint
```
yarn lint
```

Env files: `.env.localhost`, `.env.dev`, `.env.staging`, `.env.prod` set `VITE_API_URL`
and `VITE_PORTAL_API_KEY` per environment. NOTE: the localhost env file is deliberately
NOT named `.env.local` — Vite loads a file with that exact name into every mode as a
local override, which would leak localhost values into dev/staging/prod builds.

`yarn.lock` is committed so CI builds are pinned — regenerate it when changing deps.
