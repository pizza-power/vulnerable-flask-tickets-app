from enum import unique
from . import db
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash


class User(UserMixin, db.Model):
    """User account model."""

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(
        db.String(200), primary_key=False, unique=False, nullable=False
    )
    isadmin = db.Column(db.Boolean(), default=False)
    created_on = db.Column(
        db.DateTime, index=False, unique=False, nullable=True
    )
    last_login = db.Column(
        db.DateTime, index=False, unique=False, nullable=True
    )

    def set_password(self, password):
        """Create hashed password."""
        self.password = generate_password_hash(password, method="sha256")

    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password, password)

    def __repr__(self):

        return "<email {} isadmin={}>".format(self.email, self.isadmin)


class Post(db.Model):
    """ Ticket Posts Model"""

    def __init__(self, ticket_number, body, attachment=None):
        self.ticket_number = ticket_number
        self.body = body
        self.attachment = attachment

    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)

    ticket_number = db.Column(db.Integer, unique=True, nullable=True)

    body = db.Column(db.String(1000), unique=False, nullable=False)

    attachment = db.Column(db.String(300), unique=False, nullable=True)

    def __repr__(self):
        return "<Post {}:{}>".format(self.id, self.body)
