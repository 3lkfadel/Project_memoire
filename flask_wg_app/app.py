# app.py
from flask import Flask, redirect, url_for
from flask_socketio import SocketIO
import sys, os
sys.path.append(os.path.dirname(__file__))


# --- Blueprints ---
from routes.dashboard import bp as dashboard_bp
from routes.peers import bp as peers_bp
from routes.server import bp as server_bp
from routes.logs import bp as logs_bp
from routes.terminal import bp as terminal_bp, init_socketio
from routes.setup import bp as setup_bp




def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # Clé de session (remplace en prod)
    app.secret_key = "dev-secret-key"
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    # Enregistrement des blueprints
    app.register_blueprint(dashboard_bp)                 # "/"
    app.register_blueprint(peers_bp,    url_prefix="/peers")
    app.register_blueprint(server_bp,   url_prefix="/server")
    app.register_blueprint(logs_bp,     url_prefix="/logs")
    app.register_blueprint(terminal_bp, url_prefix="/terminal")
    app.register_blueprint(setup_bp,    url_prefix="/setup")

    # Option: rediriger / vers le dashboard si ton dashboard est ailleurs
    @app.route("/home")
    def _home_redirect():
        return redirect(url_for("dashboard.home"))

    return app

# --- Création de l'app + Socket.IO ---
app = create_app()
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# Brancher les handlers WebSocket définis dans routes/terminal.py
init_socketio(socketio)

if __name__ == "__main__":
    # Lancer le serveur
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
