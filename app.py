"""Entry point:  python app.py"""
from config import ensure_env_file

ensure_env_file()

from app import create_app  # noqa: E402  (must run after the .env exists)

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=app.config["DEBUG"])
