"""Flask integration.  pip install flask && python examples/flask_app.py"""
import logging
import os

from flask import Flask, Response

from artex_shield import Config, Shield, ShieldWSGI, html_trap, js_trap, make_canaries, robots_txt_block

logging.basicConfig(level=logging.INFO, format="%(message)s")

canaries = make_canaries(os.environ.get("SHIELD_SECRET", "change-me"))
shield = Shield(Config(mode=os.environ.get("SHIELD_MODE", "monitor"), canary_paths=canaries,
                       exempt_paths=["/healthz"]))

app = Flask(__name__)
app.wsgi_app = ShieldWSGI(app.wsgi_app, shield)


@app.get("/")
def home():
    return f"<h1>Hello</h1>{html_trap(canaries[1])}<script src='/static/app.js'></script>"


@app.get("/static/app.js")
def bundle():
    return Response(f"console.log('app');\n{js_trap(canaries[0])}\n", mimetype="application/javascript")


@app.get("/robots.txt")
def robots():
    return Response(robots_txt_block(canaries), mimetype="text/plain")


@app.get("/healthz")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(port=8000)
