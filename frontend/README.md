# BankSentinel (frontend)

Scaffolded frontend for the BankSentinel IDS dashboard.

Prerequisites:
- Node 20 LTS
- Docker (for containerized build)

Quick start:

1. Copy `.env.example` to `.env.development` and adjust values.
2. Install dependencies:

```bash
npm ci
```

3. Development:

```bash
npm run dev
```

4. Build:

```bash
npm run build
```

Docker:

```bash
docker-compose up --build
```

This repository is a scaffold implementing the project's architecture and
initial service layer mocks. Continue implementing features per the
`frontend_build_detail.md` specification.
