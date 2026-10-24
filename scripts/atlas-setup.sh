#!/usr/bin/env bash
# One-shot MongoDB Atlas setup for the dRouter demo. Run after `atlas auth login`.
# Creates (or reuses) a "drouter" project and a free M0 cluster, creates an app user with
# readWrite on the "drouter" database only, writes MONGODB_URI to .env.local and to the
# Vercel production environment. Never prints the password.
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT_NAME=drouter
CLUSTER=drouter
DB_USER=drouter-app

project_id=$(atlas projects list --output json | node -e '
  let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    const list = JSON.parse(s).results ?? [];
    const p = list.find((x) => x.name === process.argv[1]);
    process.stdout.write(p ? p.id : "");
  });' "$PROJECT_NAME")
if [ -z "$project_id" ]; then
  project_id=$(atlas projects create "$PROJECT_NAME" --output json | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s).id))')
  echo "created project $PROJECT_NAME"
fi

if ! atlas clusters describe "$CLUSTER" --projectId "$project_id" >/dev/null 2>&1; then
  atlas clusters create "$CLUSTER" --projectId "$project_id" --provider AWS --region US_EAST_1 --tier M0 >/dev/null
  echo "creating free M0 cluster $CLUSTER (a few minutes)..."
fi
atlas clusters watch "$CLUSTER" --projectId "$project_id"

# Vercel functions use dynamic egress IPs, so the demo allows all addresses; access still needs
# the database password. Restrict this before any non-demo use.
atlas accessLists create 0.0.0.0/0 --type cidrBlock --comment "drouter demo (Vercel)" --projectId "$project_id" >/dev/null 2>&1 || true

password=$(openssl rand -hex 24)
atlas dbusers delete "$DB_USER" --projectId "$project_id" --force >/dev/null 2>&1 || true
atlas dbusers create --username "$DB_USER" --password "$password" --role readWrite@drouter --projectId "$project_id" >/dev/null

srv=$(atlas clusters connectionStrings describe "$CLUSTER" --projectId "$project_id" --output json | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s).standardSrv))')
uri="${srv/mongodb+srv:\/\//mongodb+srv://$DB_USER:$password@}/drouter?retryWrites=true&w=majority&appName=drouter-demo"

tmp=$(mktemp)
grep -v '^MONGODB_URI=' .env.local > "$tmp" || true
printf 'MONGODB_URI=%s\n' "$uri" >> "$tmp"
mv "$tmp" .env.local && chmod 600 .env.local
printf '%s' "$uri" | vercel env add MONGODB_URI production --force >/dev/null
echo "MONGODB_URI written to .env.local and Vercel production env"
