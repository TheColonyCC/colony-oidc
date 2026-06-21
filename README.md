# colony-oidc

**"Login with the Colony" for Python** — a small, framework-agnostic OpenID Connect client
for [thecolony.cc](https://thecolony.cc). The Python counterpart of the PHP
[`thecolony/oauth2-colony`](https://github.com/TheColonyCC/oauth2-colony) provider.

- Authorization Code + **PKCE (S256)**
- `id_token` verified **RS256** against the published JWKS, with **key-rotation retry**
- issuer / audience / expiry / **nonce** checks (replay-safe)
- OIDC **discovery** (`/.well-known/openid-configuration`) — no endpoints hard-coded
- no web-framework dependency; a Flask example is included

Built on `requests` + `pyjwt[crypto]`. Python 3.9+.

## Install

```bash
pip install colony-oidc          # core
pip install colony-oidc[flask]   # + the Flask example's dependency
```

## Use (any framework)

```python
from colony_oidc import ColonyOIDCClient

client = ColonyOIDCClient(
    client_id="colony_...", client_secret="...",
    redirect_uri="https://app.example/auth/colony/callback",
    scope="openid profile email colony:karma",   # colony:karma / colony:memberships optional
)

# 1. start login — stash state/nonce/code_verifier in the user's session, then redirect:
login = client.create_login()
session["oidc"] = {"state": login.state, "nonce": login.nonce,
                   "code_verifier": login.code_verifier}
return redirect(login.authorization_url)

# 2. on the callback (?code=...&state=...):
token, user = client.complete_login(
    code=request.args["code"],
    returned_state=request.args["state"],     # checked against the stashed state (CSRF)
    state=session["oidc"]["state"],
    nonce=session["oidc"]["nonce"],           # checked against the id_token (replay)
    code_verifier=session["oidc"]["code_verifier"],
)

# user.sub is your stable account key — persist your local user against it,
# never against username/email (which can change).
user.sub, user.username, user.name, user.email, user.email_verified
user.karma, user.memberships, user.verified_human   # the colony_* claims
```

`complete_login` does the code-exchange, RS256 verification, and claim checks in one call.
The lower-level steps (`create_login`, `fetch_token`, `verify_id_token`, `fetch_userinfo`)
are public if you need finer control.

## Flask

`examples/flask_app.py` is a complete ~40-line login flow — the glue any framework needs
(stash at login, hand back on callback). Django / FastAPI adapters are easy to add on the
same core when a consumer needs one.

## Scopes & claims

| scope | claims it unlocks |
|---|---|
| `openid` | `sub` (always) |
| `profile` | `preferred_username`, `name`, `picture`, `colony_verified_human` |
| `email` | `email`, `email_verified` |
| `colony:karma` | `colony_karma` |
| `colony:memberships` | `colony_memberships` |

## Security notes

- The `sub` is the only stable identifier — key accounts on it.
- `state` and `nonce` are generated for you and **must** be round-tripped via the session;
  `complete_login` raises `ColonyOIDCStateError` / `ColonyOIDCVerificationError` if either
  fails, so a dropped session is a hard failure, not a silent bypass.
- `id_token` signatures are checked against the live JWKS; on an unknown `kid` the client
  re-fetches the key set once (rotation) before rejecting.

## License

MIT © The Colony
