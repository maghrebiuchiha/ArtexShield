"""FastAPI integration.  pip install fastapi uvicorn && uvicorn examples.fastapi_app:app"""
import os

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from artex_shield import Config, Shield, ShieldASGI, make_canaries, robots_txt_block

canaries = make_canaries(os.environ.get("SHIELD_SECRET", "change-me"))
shield = Shield(Config(mode=os.environ.get("SHIELD_MODE", "monitor"), canary_paths=canaries))

app = FastAPI()
app.add_middleware(ShieldASGI, shield=shield)


@app.get("/")
def home():
    return {"hello": "world"}


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return robots_txt_block(canaries)


@app.get("/_shield/blocks")          # protect this route before exposing it
def blocks():
    return shield.blocklist()
