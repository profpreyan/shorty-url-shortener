
from datetime import datetime, timedelta
import os
import re
import string
import random
from flask import Flask, request, redirect, render_template, url_for, jsonify, abort, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from functools import wraps
from flask import Response


# --- Config ---
BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")  # optional for protecting admin pages

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")  # replace in production
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///data.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
BASIC_AUTH_USER = os.environ.get("BASIC_AUTH_USER", "")
BASIC_AUTH_PASS = os.environ.get("BASIC_AUTH_PASS", "")

def _auth_failed_response():
    # This tells the browser to show a login popup
    return Response('Login required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

def _needs_auth(path: str) -> bool:
    """
    Protect admin & UI pages, but keep short-link redirects public.
    Public: /<slug>, /healthz
    Protected: / (home), /create, /admin/*, /stats/*, /api/*
    """
    if not BASIC_AUTH_USER:
        return False  # if no creds set, keep site open
    if path == "/healthz":
        return False
    if path == "/":
        return True
    for prefix in ("/create", "/admin", "/stats", "/api"):
        if path.startswith(prefix):
            return True
    return False  # everything else (like /abc123) is a public redirect

@app.before_request
def _basic_auth_gate():
    if not BASIC_AUTH_USER:
        return  # no auth configured
    if _needs_auth(request.path):
        auth = request.authorization
        if not auth or not (auth.username == BASIC_AUTH_USER and auth.password == BASIC_AUTH_PASS):
            return _auth_failed_response()

# --- Models ---
class Link(db.Model):
    __tablename__ = "links"
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    target_url = db.Column(db.Text, nullable=False)
    title = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    clicks = db.relationship("Click", backref="link", lazy=True, cascade="all,delete")

class Click(db.Model):
    __tablename__ = "clicks"
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey("links.id"), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.Text)
    referer = db.Column(db.Text)
    accept_language = db.Column(db.String(255))

# --- Helpers ---
SLUG_REGEX = re.compile(r"^[a-zA-Z0-9-_]{1,50}$")

def random_slug(n=6):
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(n))

def is_admin(req):
    # If no token is configured, leave the app open (useful for local demos).
    if not ADMIN_TOKEN:
        return True
    # Accept token from querystring, header, or POST form body.
    token = (
        req.args.get("token")
        or req.headers.get("X-Admin-Token")
        or req.form.get("token")
    )
    return token == ADMIN_TOKEN


# Run init only once before the first request
@app.before_request
def init_db_once():
    if not hasattr(app, "_db_initialized"):
        db.create_all()
        app._db_initialized = True

@app.get("/")
def home():
    # List recent links
    recent = Link.query.order_by(Link.created_at.desc()).limit(20).all()
    return render_template("index.html", base_url=BASE_URL, recent=recent, admin_token=ADMIN_TOKEN)

@app.post("/create")
def create():
    if not is_admin(request):
        abort(403)
    target_url = request.form.get("target_url","").strip()
    custom_slug = request.form.get("custom_slug","").strip()
    title = request.form.get("title","").strip()

    if not target_url:
        flash("Target URL is required.", "error")
        return redirect(url_for("home"))

    if custom_slug:
        if not SLUG_REGEX.match(custom_slug):
            flash("Invalid slug. Use 1–50 characters: letters, numbers, - or _", "error")
            return redirect(url_for("home"))
        slug = custom_slug
    else:
        # generate unique random slug
        slug = random_slug()
        tries = 0
        while Link.query.filter_by(slug=slug).first():
            slug = random_slug()
            tries += 1
            if tries > 10:
                flash("Could not generate a unique slug. Try again.", "error")
                return redirect(url_for("home"))

    # Ensure uniqueness if provided
    if Link.query.filter_by(slug=slug).first():
        flash("Slug already exists. Choose a different one.", "error")
        return redirect(url_for("home"))

    link = Link(slug=slug, target_url=target_url, title=title or None)
    db.session.add(link)
    db.session.commit()
    flash("Short link created.", "success")
    return redirect(url_for("home"))

@app.get("/admin/links")
def admin_links():
    if not is_admin(request):
        abort(403)
    links = Link.query.order_by(Link.created_at.desc()).all()
    return render_template("links.html", links=links, base_url=BASE_URL, admin_token=ADMIN_TOKEN)
from flask import flash  # at the top with imports (harmless if unused)

# --- Edit link (update target_url) ---
@app.route("/admin/edit/<int:link_id>", methods=["POST"])
def admin_edit_link(link_id):
    if not is_admin(request):
        return "Forbidden", 403
    link = Link.query.get_or_404(link_id)
    new_url = request.form.get("target_url", "").strip()
    if not new_url:
        return "Target URL required", 400
    link.target_url = new_url
    db.session.commit()
    return redirect(url_for("admin_links") + f"?token={request.args.get('token','')}")

# --- Delete link ---
@app.route("/admin/delete/<int:link_id>", methods=["POST"])
def admin_delete_link(link_id):
    if not is_admin(request):
        return "Forbidden", 403
    link = Link.query.get_or_404(link_id)
    # delete its clicks too
    Click.query.filter_by(link_id=link.id).delete()
    db.session.delete(link)
    db.session.commit()
    return redirect(url_for("admin_links") + f"?token={request.args.get('token','')}")

# --- Edit link (update target_url) by slug ---
@app.route("/admin/edit/<slug>", methods=["POST"])
def admin_edit_link_slug(slug):
    if not is_admin(request):
        return "Forbidden", 403
    link = Link.query.filter_by(slug=slug).first_or_404()
    new_url = (request.form.get("target_url") or "").strip()
    if not new_url:
        return "Target URL required", 400
    link.target_url = new_url
    db.session.commit()
    # keep token in query so you stay authenticated
    return redirect(url_for("admin_links") + f"?token={request.args.get('token','')}")

# --- Delete link by slug ---
@app.route("/admin/delete/<slug>", methods=["POST"])
def admin_delete_link_slug(slug):
    if not is_admin(request):
        return "Forbidden", 403
    link = Link.query.filter_by(slug=slug).first_or_404()
    # remove its analytics
    Click.query.filter_by(link_id=link.id).delete()
    db.session.delete(link)
    db.session.commit()
    return redirect(url_for("admin_links") + f"?token={request.args.get('token','')}")


@app.post("/admin/delete/<slug>")
def delete_link(slug):
    if not is_admin(request):
        abort(403)
    link = Link.query.filter_by(slug=slug).first_or_404()
    db.session.delete(link)
    db.session.commit()
    flash(f"Deleted {slug}", "success")
    return redirect(url_for("admin_links"))

@app.get("/stats/<slug>")
def stats_page(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()
    return render_template("link_stats.html", link=link, base_url=BASE_URL, admin_token=ADMIN_TOKEN)

@app.get("/api/stats/<slug>.json")
def stats_api(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()

    # Last 30 days daily click counts
    today = datetime.utcnow().date()
    start_date = today - timedelta(days=29)
    # Query clicks grouped by date
    daily = (
        db.session.query(func.date(Click.timestamp), func.count(Click.id))
        .filter(Click.link_id == link.id, Click.timestamp >= start_date)
        .group_by(func.date(Click.timestamp))
        .all()
    )
    daily_map = {str(d): c for d, c in daily}
    labels = [str(start_date + timedelta(days=i)) for i in range(30)]
    counts = [daily_map.get(label, 0) for label in labels]

    # Top referrers (null/empty categorized as "direct")
    ref_rows = (
        db.session.query(Click.referer, func.count(Click.id))
        .filter(Click.link_id == link.id)
        .group_by(Click.referer)
        .order_by(func.count(Click.id).desc())
        .limit(8)
        .all()
    )
    referrers = []
    for r, c in ref_rows:
        referrers.append({
            "referer": r if r else "direct",
            "count": int(c)
        })

    # Top user agents (simplified)
    ua_rows = (
        db.session.query(Click.user_agent, func.count(Click.id))
        .filter(Click.link_id == link.id)
        .group_by(Click.user_agent)
        .order_by(func.count(Click.id).desc())
        .limit(8)
        .all()
    )
    user_agents = [{"user_agent": ua or "unknown", "count": int(c)} for ua, c in ua_rows]

    # Unique visitors (very rough): distinct (ip, user_agent)
    unique_visitors = (
        db.session.query(func.count(func.distinct(func.concat(Click.ip, "||", Click.user_agent))))
        .filter(Click.link_id == link.id)
        .scalar()
    )
    total_clicks = db.session.query(func.count(Click.id)).filter(Click.link_id == link.id).scalar()

    return jsonify({
        "slug": link.slug,
        "target_url": link.target_url,
        "title": link.title,
        "labels": labels,
        "daily_counts": counts,
        "referrers": referrers,
        "user_agents": user_agents,
        "total_clicks": int(total_clicks or 0),
        "unique_visitors": int(unique_visitors or 0),
    })

@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.get("/<slug>")
def redirect_slug(slug):
    link = Link.query.filter_by(slug=slug).first()
    if not link:
        abort(404)
    # Log click
    try:
        click = Click(
            link_id = link.id,
            ip = request.headers.get("X-Forwarded-For", request.remote_addr),
            user_agent = request.headers.get("User-Agent"),
            referer = request.headers.get("Referer"),
            accept_language = request.headers.get("Accept-Language"),
        )
        db.session.add(click)
        db.session.commit()
    except Exception as e:
        app.logger.exception("Failed to log click: %s", e)
        db.session.rollback()
    return redirect(link.target_url, code=302)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
