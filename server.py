import logging
import os
import ssl
import threading

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

import config
from fog_node import FogNode


def create_app(fog):
    app = Flask("iiot-fog")

    def body():
        return request.get_json(silent=True) or {}

    def require_admin():
        if request.headers.get("X-Admin-Key") != config.ADMIN_API_KEY:
            raise PermissionError("admin key required")

    # any ValueError from our fog code becomes HTTP 400 with the reason
    @app.errorhandler(ValueError)
    def bad_request(e):
        return jsonify({"error": str(e)}), 400

    @app.errorhandler(PermissionError)
    def forbidden(e):
        return jsonify({"error": str(e)}), 403

    # ---------------- Phase 1: onboarding ----------------
    @app.post("/register/start")
    def register_start():
        b = body()
        return jsonify({"session_id": fog.register_start(b["device_name"], b["timestamp"], b["mac"])})

    @app.post("/register/pubkey")
    def register_pubkey():
        b = body()
        return jsonify({"challenge": fog.register_pubkey(b["session_id"], b["public_key"])})

    @app.post("/register/pop")
    def register_pop():
        b = body()
        return jsonify({"ok": fog.register_pop(b["session_id"], b["signature"])})

    @app.post("/register/submit")
    def register_submit():
        b = body()
        return jsonify(fog.register_submit(b["session_id"], b["did"], b["metadata"],
                                           b.get("want_token", False), b.get("token_ttl")))

    @app.post("/proof")
    def proof():
        return jsonify({"package": fog.get_proof_package(body()["did"])})

    # ---------------- Phase 2 / 3: access ----------------
    @app.post("/access/challenge")
    def challenge():
        return jsonify({"nonce": fog.get_challenge(body()["did"])})

    @app.post("/access/request")
    def access():
        return jsonify(fog.access(body()))

    # ---------------- operator (admin) ----------------
    @app.post("/admin/finalize")
    def finalize():
        require_admin()
        return jsonify(fog.finalize_epoch())

    @app.post("/admin/revoke-device")
    def revoke_device():
        require_admin()
        b = body()
        return jsonify({"revoked_tokens": fog.revoke_device(b["did"], b.get("reason", "revoked"))})

    @app.post("/admin/revoke-token")
    def revoke_token():
        require_admin()
        b = body()
        return jsonify({"ok": fog.revoke_token(b["token_id"], b.get("reason", "revoked"))})

    @app.get("/registry/chain")
    def chain():
        return jsonify({"valid": fog.registry.verify_chain(), "blocks": fog.registry.blocks})

    logging.getLogger("werkzeug").setLevel(logging.ERROR)     # keep the demo output clean
    return app


def tls_context():
    if not os.path.exists(config.FOG_CERT):
        from gen_certs import generate
        generate()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(config.FOG_CERT, config.FOG_KEY)
    return ctx


def start_in_background(fog, port=config.FOG_PORT):
    """Runs the HTTPS server in a background thread (for single-script demos)."""
    server = make_server(config.FOG_HOST, port, create_app(fog), threaded=True, ssl_context=tls_context())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server                     # call server.shutdown() when finished


if __name__ == "__main__":
    fog = FogNode()
    print(f"Fog node listening on https://{config.FOG_HOST}:{config.FOG_PORT}  (Ctrl+C to stop)")
    make_server(config.FOG_HOST, config.FOG_PORT, create_app(fog),
                threaded=True, ssl_context=tls_context()).serve_forever()