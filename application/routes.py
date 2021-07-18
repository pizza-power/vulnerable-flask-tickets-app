from types import MethodType
import os, pickle, base64
from flask import current_app as app
from flask import (
    Markup,
    json,
    redirect,
    make_response,
    render_template,
    flash,
    request,
    session,
    url_for,
    send_from_directory,
)
from flask_login import login_required, logout_user, current_user, login_user
from flask_user import roles_required
from werkzeug.security import generate_password_hash
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
from functools import wraps
from .forms import AttachmentForm, LoginForm, RegisterForm
from .models import User, Post
from . import db
from . import login_manager


@app.route("/home", methods=["GET"])
@app.route("/index", methods=["GET"])
@app.route("/", methods=["GET"])
def home():
    if request.method != "GET":
        return make_response("Method not supported", 405)
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if current_user.is_authenticated:
        return redirect(url_for(".home"))

    if request.method == "POST":
        if form.validate_on_submit():
            email = request.form.get("email")
            password = request.form.get("password")

            existing_user = User.query.filter_by(email=email).first()
            if existing_user is None:
                user = User(
                    email=email,
                    password=generate_password_hash(password, method="sha256"),
                )
                user.set_password(form.password.data)
                db.session.add(user)
                db.session.commit()
                login_user(user)
                return redirect(url_for(".home"))

    return render_template(
        "register.html",
        title="Register",
        form=form,
        description="Register",
        body="Register pizza",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for(".home"))

    form = LoginForm()
    # validation
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(password=form.password.data):
            login_user(user)
            next_page = request.args.get("next")
            return redirect(next_page or url_for(".home"))

        flash("Invalid username and/or password")
        return redirect(url_for(".login"))
    return render_template(
        "login.html",
        form=form,
        title="Log in.",
        template="login",
        body="login with your account.",
        description="login",
    )


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps(
        {
            "code": e.code,
            "name": e.name,
            "description": e.description,
        }
    )
    response.content_type = "application/json"
    return response


@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        return User.query.get(user_id)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    flash("Please log in to continue.")
    return redirect(url_for(".login"))


# ------------------------authorization required pages ----------------------


@app.route("/logout")
@login_required
def logout():
    # TODO: add some sort of message or redirect to logout/login page with note?
    logout_user()
    return redirect(url_for(".home"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """
    GET gets the user profile
    POST edits the user profile
    """
    if request.method == "GET":
        return render_template(
            "profile.html",
            title="This is your profile!",
            description="profile",
            current_user=current_user,
            body="you are logged in!",
        )
    if request.method == "POST":
        return render_template(
            "profile.html",
            title="Edit your profile!",
            description="edit",
            current_user=current_user,
            body="Edit your profile!",
        )
    else:
        flash("Method not allowed!")
        return redirect(url_for(".profile"))


@app.route("/posts", methods=["GET"])
@login_required
def posts():
    """gets posts and posts posts"""
    posts = Post.query.all()
    form = AttachmentForm("attach file")

    if request.method == "GET":
        return render_template(
            "posts.html", posts=posts, form=form, title=">Tickets"
        )


# -------------- admin functions ------------------------------


@app.route("/attach/<id>", methods=["GET", "POST"])
@login_required
def attach(id):
    if request.method == "GET":
        form = AttachmentForm("attach file")
        return render_template("attach.html", form=form, id=id)
    elif request.method == "POST":
        print(request.data)
        if not current_user.isadmin:
            print("user not admin")
            return
        else:
            file = request.files["file"]

            if file.filename == "":
                flash("No file selected!")
                return redirect(url_for(".attach"))

            if file and allowed_file(file.filename):
                # TODO: Vuln, secure_filename sanitizes, see
                # https://flask.palletsprojects.com/en/2.0.x/patterns/fileuploads/
                filename = secure_filename(file.filename)
                filepath = os.path.join(
                    app.config["ATTACHMENTS_DIR"], filename
                )

                # TODO: check if file already exists, or it will overwrite the previous one

                file.save(filepath)

                # update post in the database
                post = Post.query.get(id)
                post.attachment = filepath
                db.session.commit()

                return redirect(url_for(".posts"))
            else:
                return redirect(url_for(".posts"))


@app.route("/archive/<id>", methods=["POST"])
@login_required
def archive(id):
    """ 
    archives json'd and pickled tickets so we can send them to our
    monitoring apps
    """
    if request.method == "GET":
        return redirect(url_for(".posts"))
    else:
        # testing archiving and then testing loading pickled posts
        # should i json encode it? https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/
        # why would this be done irl
        post = Post.query.get(id)
        data = base64.urlsafe_b64encode(pickle.dumps(post.body + str(post.id)))
        filename = id + ".pickle"
        filepath = os.path.join(app.config["ATTACHMENTS_DIR"], filename)
        f = open(filepath, "wb")
        f.write(data)
        f.close()

        # load to trigger vuln, put this in other app
        # f = open(filepath, "rb")
        # pickle.loads(base64.b64decode(f.read()))

        return redirect(url_for(".posts"))


@app.route("/restore/<id>", methods=["GET"]) # or post or ?
@login_required
def restore(id):
    return render_template(url_for(".posts"))



# ------------------------ File Functions and Routes ---------------------------


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in app.config["ALLOWED_EXTENSIONS"]
    )


@app.route("/attachments/<filename>")
@login_required
def uploaded_file(filename):
    print(filename)
    # TODO: fix this hardcoded path when refactoring
    return send_from_directory(
        "/home/user/data/programming/vuln-flask-app/app/application/attachments",
        filename,
    )
