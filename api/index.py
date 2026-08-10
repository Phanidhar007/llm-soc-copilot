"""Live dashboard for llm-soc-copilot.

Self-contained Flask app that renders the committed results/metrics.md plus the
results/figures/*.png charts with the AI Shield dark theme. Uses only stdlib +
flask (no numpy/sklearn/torch at request time) so it runs on the lightweight
Vercel Python runtime even for torch-based projects.

Run locally:
    python api/index.py
    # then open http://127.0.0.1:7860/
"""

import html
import os
import re
import sys

from flask import Flask, Response, abort

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)

REPO = "llm-soc-copilot"
REPO_URL = "https://github.com/Phanidhar007/llm-soc-copilot"

_CSS = """
  :root {
    --bg:#030303; --card:#09090b; --card-95:rgba(9,9,11,.95);
    --border:#18181b; --border-strong:#27272a;
    --emerald-400:#34d399; --emerald-500:#10b981;
    --red-400:#f87171; --amber-400:#fbbf24; --purple-400:#c084fc;
    --text:#ffffff; --text-2:#d4d4d8; --text-3:#a1a1aa; --text-4:#71717a;
    --font-heading:"Space Grotesk",sans-serif; --font-body:"Plus Jakarta Sans",sans-serif;
    --font-mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:var(--font-body); line-height:1.6; }
  h1,h2,h3,h4 { font-family:var(--font-heading); letter-spacing:-.02em; margin:0 0 .5rem; }
  .grad-title { background:linear-gradient(135deg,#fff,#f4f4f5 50%,#a1a1aa);
    -webkit-background-clip:text; background-clip:text; color:transparent; }
  .grad-accent { background:linear-gradient(90deg,#34d399,#5eead4,#06b6d2);
    -webkit-background-clip:text; background-clip:text; color:transparent; }
  .wrap { max-width:1080px; margin:0 auto; padding:2rem 1.5rem 4rem; }
  .nav { position:sticky; top:0; z-index:10; background:rgba(3,3,3,.85); backdrop-filter:blur(12px);
    border-bottom:1px solid rgba(255,255,255,.05); }
  .nav-inner { max-width:1080px; margin:0 auto; padding:.8rem 1.5rem; display:flex; align-items:center;
    justify-content:space-between; }
  .brand { display:flex; align-items:center; gap:10px; font-family:var(--font-heading);
    font-weight:700; font-size:1.05rem; }
  .brand .dot { width:10px; height:10px; border-radius:50%; background:var(--emerald-400);
    box-shadow:0 0 10px var(--emerald-500); }
  .pill { display:inline-flex; align-items:center; gap:8px; padding:8px 16px; border-radius:9999px;
    background:rgba(24,24,27,.6); border:1px solid var(--border-strong); color:var(--text-3);
    font-family:var(--font-mono); font-size:12px; text-decoration:none; transition:all .15s; }
  .pill:hover { background:rgba(39,39,42,.8); color:#fff; }
  .card { border-radius:16px; border:1px solid var(--border); background:var(--card-95);
    box-shadow:0 20px 50px rgba(0,0,0,.85); padding:20px; margin-bottom:16px; }
  .section-label { font-family:var(--font-mono); font-size:11px; color:var(--emerald-400);
    letter-spacing:.15em; text-transform:uppercase; margin-bottom:6px; display:block; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin:8px 0 16px; }
  th { font-family:var(--font-mono); font-size:10px; letter-spacing:.1em; text-transform:uppercase;
    color:var(--text-4); text-align:left; padding:8px 10px; border-bottom:1px solid var(--border-strong); }
  td { padding:8px 10px; border-bottom:1px solid var(--border); color:var(--text-2); }
  tr:hover td { background:rgba(255,255,255,.02); }
  .mono { font-family:var(--font-mono); }
  .muted { color:var(--text-3); }
  .hint { font-family:var(--font-mono); font-size:11px; color:var(--text-4);
    letter-spacing:.08em; text-transform:uppercase; }
  code { font-family:var(--font-mono); font-size:12px; background:rgba(0,0,0,.5);
    border:1px solid var(--border); border-radius:6px; padding:1px 6px; color:var(--emerald-400); }
  ul { margin:8px 0 16px; padding-left:20px; }
  li { margin:4px 0; color:var(--text-2); font-size:13px; }
  .fig { border-radius:16px; border:1px solid var(--border); overflow:hidden; margin:0 0 24px;
    background:var(--card-95); }
  .fig img { width:100%; display:block; border-bottom:1px solid var(--border); }
  .fig .cap { padding:10px 16px; font-family:var(--font-mono); font-size:11px; color:var(--text-4); }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:0 0 24px; }
  .stat { padding:16px; border-radius:16px; border:1px solid var(--border); background:var(--card-95); }
  .stat .k { font-family:var(--font-mono); font-size:10px; color:var(--text-4); text-transform:uppercase;
    letter-spacing:.12em; }
  .stat .v { font-family:var(--font-mono); font-size:22px; font-weight:800; color:var(--emerald-400); }
  p { color:var(--text-2); font-size:14px; }
  .footer { border-top:1px solid rgba(255,255,255,.05); padding:2rem 1.5rem; text-align:center;
    color:var(--text-4); font-size:13px; }
  a { color:var(--emerald-400); text-decoration:none; }
  a:hover { text-decoration:underline; }
"""


def _inline(text):
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    return text


def _render_md(md):
    """Minimal markdown -> HTML for the generated metrics.md files."""
    out = []
    i = 0
    lines = md.splitlines()
    # skip the H1 title line (rendered separately)
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith("## "):
            out.append(
                '<span class="section-label">%s</span><h2 class="grad-accent">%s</h2>'
                % (html.escape(stripped[3:]), html.escape(stripped[3:]))
            )
            i += 1
            continue
        if stripped.startswith("```"):
            buf = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            out.append("<pre class='mono'>%s</pre>" % html.escape("\n".join(buf)))
            continue
        if stripped.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i].strip())
                i += 1
            out.append(_render_table(rows))
            continue
        if stripped.startswith("- ") or stripped.startswith("* "):
            buf = []
            while i < len(lines) and (lines[i].strip().startswith("- ") or lines[i].strip().startswith("* ")):
                buf.append(lines[i].strip())
                i += 1
            items = "".join("<li>%s</li>" % _inline(b[2:]) for b in buf)
            out.append("<ul>%s</ul>" % items)
            continue
        # plain paragraph
        out.append("<p>%s</p>" % _inline(stripped))
        i += 1
    return "\n".join(out)


def _render_table(rows):
    def split(row):
        row = row.strip()
        if row.startswith("|"):
            row = row[1:]
        if row.endswith("|"):
            row = row[:-1]
        return [c.strip() for c in row.split("|")]

    header = split(rows[0])
    body = []
    for r in rows[1:]:
        cells = split(r)
        if cells and all(re.fullmatch(r"[-:]+", c or "") for c in cells):
            continue  # separator row
        body.append(cells)
    thead = "<thead><tr>%s</tr></thead>" % "".join(
        "<th>%s</th>" % _inline(c) for c in header
    )
    tbody = "<tbody>%s</tbody>" % "".join(
        "<tr>%s</tr>" % "".join("<td>%s</td>" % _inline(c) for c in row) for row in body
    )
    return "<table>%s%s</table>" % (thead, tbody)


def _figures_html():
    figs_dir = os.path.join(BASE, "results", "figures")
    if not os.path.isdir(figs_dir):
        return ""
    names = sorted(os.listdir(figs_dir))
    blocks = []
    for name in names:
        if not name.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
            continue
        blocks.append(
            '<div class="fig"><img alt="%s" src="/figures/%s" loading="lazy">'
            '<div class="cap">%s</div></div>'
            % (html.escape(name), html.escape(name), html.escape(name))
        )
    return "\n".join(blocks)


def _stats_html(md):
    """Extract a few headline `key: value`-style bullets as stat cards."""
    cards = []
    seen = 0
    for line in md.splitlines():
        m = re.match(r"\s*[-*]\s+(.+?):\s*(`[^`]+`|[\d.,%]+)\s*$", line)
        if not m:
            continue
        k = m.group(1).replace("**", "").strip()
        v = m.group(2).strip().strip("`")
        if seen >= 6:
            break
        cards.append('<div class="stat"><div class="k">%s</div><div class="v">%s</div></div>' % (_inline(k), _inline(v)))
        seen += 1
    return '<div class="stats">%s</div>' % "".join(cards) if cards else ""


def _page():
    md_path = os.path.join(BASE, "results", "metrics.md")
    if os.path.exists(md_path):
        with open(md_path, "r", encoding="utf-8") as f:
            md = f.read()
    else:
        md = "No results/metrics.md found yet. Run `python scripts/run_pipeline.py` locally to generate it."
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>%s - results</title>"
        '<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300..700&family=Plus+Jakarta+Sans:wght@400..700&display=swap" rel="stylesheet">'
        "<style>%s</style></head><body>"
        '<nav class="nav"><div class="nav-inner">'
        '<div class="brand"><span class="dot"></span>%s</div>'
        '<a class="pill" href="%s" target="_blank" rel="noopener">View on GitHub</a>'
        "</div></nav>"
        '<div class="wrap">'
        '<span class="section-label">Security ML - live results dashboard</span>'
        '<h1 class="grad-title">%s</h1>'
        '<p class="muted">Real numbers from the committed <code>results/metrics.md</code>; '
        "charts from <code>results/figures</code>. No model is executed server-side.</p>"
        "%s%s<div style='margin-top:16px'>%s</div>"
        '<footer class="footer">%s - %s</footer>'
        "</div></body></html>"
        % (
            REPO,
            _CSS,
            REPO,
            REPO_URL,
            REPO,
            _stats_html(md),
            _render_md(md),
            _figures_html(),
            "AI Shield live results dashboard",
            REPO_URL.replace("https://", ""),
        )
    )


@app.route("/")
def index():
    return _page()


@app.route("/figures/<path:name>")
def figure(name):
    safe = os.path.normpath(name)
    if safe.startswith("..") or os.path.isabs(safe):
        abort(404)
    path = os.path.join(BASE, "results", "figures", safe)
    if not os.path.exists(path):
        abort(404)
    return Response(open(path, "rb").read(), mimetype="image/png")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860, debug=False)
