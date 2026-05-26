from flask import Flask
from flask_cors import CORS

from .routes import api


def create_app():
    app = Flask(__name__)
    CORS(app)
    app.register_blueprint(api)
    return app


def main():
    app = create_app()
    print("VulnScan API: http://localhost:5050")
    app.run(host="0.0.0.0", port=5050, debug=True)


if __name__ == "__main__":
    main()
