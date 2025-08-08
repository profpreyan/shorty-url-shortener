
# Shorty — URL Shortener with Custom Slugs & Analytics

A lightweight Flask app to create short links with custom slugs and view basic analytics
(click counts, referrers, user agents, rough unique visitors).

## Features
- Create short links with a custom slug (`my-campaign` → `https://your.domain/my-campaign`)
- Redirect tracking with IP, user agent, referer, accept-language
- Analytics dashboard: daily clicks (last 30d), referrers, user agents, totals
- Simple admin token for creation & management
- SQLite by default, swappable via `DATABASE_URL`

## Quick start (local)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export BASE_URL="http://localhost:5000"
export ADMIN_TOKEN="set-a-strong-admin-token"
export SECRET_KEY="another-secret"

python app.py
# open http://localhost:5000
```

## Deploy to Render (no DB setup needed)

1. Push this folder to a new GitHub repo.
2. In Render, create a **Web Service** from your repo.
3. Environment:
   - `Runtime`: Docker
   - Set env vars: `BASE_URL` (e.g. `https://your-domain.com`), `ADMIN_TOKEN`, `SECRET_KEY`
4. Click **Deploy**.

Render will build using the Dockerfile and run `gunicorn` on port 5000.

## Using a custom domain

Point your domain to your hosting provider and set `BASE_URL` accordingly (e.g. `https://sho.rt`).

## Endpoints

- `GET /` — create form + recent links
- `POST /create` — create a short link (requires admin token if set)
- `GET /<slug>` — redirect + log click
- `GET /stats/<slug>` — analytics page
- `GET /api/stats/<slug>.json` — analytics JSON
- `GET /admin/links` — manage links (requires admin token if set)
- `POST /admin/delete/<slug>` — delete link (requires admin token if set)

## Notes & Extensions

- Unique visitors are estimated using `(ip, user_agent)` pairs; add a cookie or user hashing for better accuracy.
- For geo analytics, integrate an IP geolocation API and store country/region on click.
- Swap SQLite for Postgres by setting `DATABASE_URL` appropriately (e.g. Render PostgreSQL).
- Add authentication (e.g., login) if you need multi-user teams.
- Add UTM parsing on redirect to bucket traffic by campaign automatically.
