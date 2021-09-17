from application import create_app
from application.models import User
from application import db
from werkzeug.security import generate_password_hash

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
