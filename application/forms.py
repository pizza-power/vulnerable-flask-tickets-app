from flask_wtf import FlaskForm, RecaptchaField
from wtforms import (
    StringField,
    TextAreaField,
    SubmitField,
    PasswordField,
    DateField,
    SelectField,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length, URL


class RegisterForm(FlaskForm):
    """Sign up for a user account."""

    email = StringField(
        "Email",
        validators=[
            Length(min=6),
            Email(message="Not a valid email address."),
            DataRequired(),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=6, message="Please enter a stronger password."),
        ],
    )
    confirmPassword = PasswordField(
        "Confirm your password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    """User Log-in Form."""

    email = StringField(
        "Email",
        validators=[DataRequired(), Email(message="Enter a valid email.")],
    )
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class AttachmentForm(FlaskForm):
    """ form used by admins to attach files to tickets"""
