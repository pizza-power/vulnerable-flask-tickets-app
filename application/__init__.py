"""Initialize app."""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.security import generate_password_hash


db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    """Construct the core app object."""
    app = Flask(__name__, instance_relative_config=False)

    # Application Configuration
    app.config.from_object("config.Config")

    # Initialize Plugins
    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from . import routes
        from .models import User, Post

        # from . import auth
        # from .assets import compile_assets

        # Register s
        # app.register_blueprint(routes.routes)

        # Create Database Models
        db.create_all()

        # create admin user
        if not User.query.all():
            email = "pizzapwr@gmail.com"
            password = "pizza123"
            print(f"admin username:{email}")
            print(f"password:{password}")
            admin = User(
                email=email,
                password=generate_password_hash(password, method="sha256"),
                info="pizza is my name, and pizza is my game",
                isadmin=True,
            )
            db.session.add(admin)
            db.session.commit()

        # create test tickets
        if not Post.query.all():
            body = "I'm having trouble with some admin functions. I backed up the code for you to look at - flasktickets.zip"
            attachment = "/home/user/data/programming/vuln-flask-app/app/application/attachments/pizza.jpeg"
            p = Post(body, attachment)
            print(f"post is: {p}")

            db.session.add(p)
            db.session.add(p)

            db.session.commit()

        # Compile static assets
        # if app.config['FLASK_ENV'] == 'development':
        #     compile_assets(app)

        return app
