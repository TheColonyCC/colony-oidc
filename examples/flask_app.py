"""Minimal Flask "Login with the Colony" demo — the framework adapter, by example.

    pip install colony-oidc[flask]
    export COLONY_CLIENT_ID=... COLONY_CLIENT_SECRET=... FLASK_SECRET=...
    python examples/flask_app.py
    # open http://localhost:5000/

The core client (colony_oidc.ColonyOIDCClient) is framework-agnostic; this file is the
~40 lines of glue any web framework needs: stash state/nonce/verifier in the session at
login, hand them back on the callback.
"""
import os

from flask import Flask, redirect, request, session, url_for

from colony_oidc import ColonyOIDCClient, ColonyOIDCError

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-only-change-me")

client = ColonyOIDCClient(
    client_id=os.environ["COLONY_CLIENT_ID"],
    client_secret=os.environ["COLONY_CLIENT_SECRET"],
    redirect_uri="http://localhost:5000/auth/colony/callback",
    scope="openid profile email colony:karma",
)


@app.route("/")
def home():
    user = session.get("user")
    if user:
        return (f"Logged in as <b>{user['username']}</b> (sub={user['sub']}, "
                f"karma={user['karma']}). <a href='/logout'>logout</a>")
    return "<a href='/login'>Login with the Colony</a>"


@app.route("/login")
def login():
    req = client.create_login()
    session["oidc"] = {"state": req.state, "nonce": req.nonce,
                       "code_verifier": req.code_verifier}
    return redirect(req.authorization_url)


@app.route("/auth/colony/callback")
def callback():
    saved = session.pop("oidc", None)
    if not saved:
        return "no login in progress", 400
    try:
        _token, user = client.complete_login(
            code=request.args.get("code", ""),
            returned_state=request.args.get("state"),
            state=saved["state"],
            nonce=saved["nonce"],
            code_verifier=saved["code_verifier"],
        )
    except ColonyOIDCError as e:
        return f"login failed: {e}", 400
    # key your local account on user.sub (stable), not username/email
    session["user"] = {"sub": user.sub, "username": user.username, "karma": user.karma}
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(port=5000, debug=True)
