from urllib.parse import urlparse, urljoin
from flask import Flask, request, render_template, redirect, url_for, flash, abort, session
from flask_login import (LoginManager, current_user, login_required,
                         login_user, logout_user, UserMixin,
                         confirm_login, fresh_login_required)
from flask_wtf import FlaskForm as Form
from wtforms import BooleanField, StringField, validators, PasswordField
import requests
from passlib.hash import sha256_crypt as pwd_context
import json
from hash_client import gen_hash
from stegano import lsb
import base64
import os

class LoginForm(Form):
    """Form for user login."""
    # for entering the username
    username = StringField('Username', [
        validators.Length(min=2, max=25, message=u"Huh? Little too short for a username."),
        validators.InputRequired(u"Forget something?")])
    
    # for entering the password
    password = PasswordField("Password", [
        validators.Length(min=2, max=25, message=u"Huh? Little too short for a password."),
        validators.InputRequired(u"Forget something?")])
    # for allowing users to choose whether to remember their login session
    remember = BooleanField('Remember me')


class RegistrationForm(Form):
    """Form for user registration."""
    
    # for entering the username
    username = StringField('Username', [
        validators.Length(min=2, max=25,
                          message=u"Huh, little too short for a username."),
        validators.InputRequired(u"Forget something?")])
    
    # for allowing users to choose whether to remember their registration
    remember = BooleanField('Remember me')
    
    # for entering the password
    password = PasswordField("Password", [
        validators.Length(min=2, max=25, message=u"Huh? Little too short for a password."),
        validators.InputRequired(u"Forget something?"), 
        validators.EqualTo('verification', message='Passwords must match')])
    
    # for verifying the password
    verification = PasswordField("Verify Password")


def is_safe_url(target):
    """
    Check if a target URL is safe by comparing its scheme and netloc with the referrer URL.

    Args:
        target (str): The target URL to be checked.

    Returns:
        bool: True if the target URL is safe, False otherwise.

    :source: https://github.com/fengsp/flask-snippets/blob/master/security/redirect_back.py
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


class User(UserMixin):
    def __init__(self, id, name):
        """
        initialize User object with the specified ID and name
        """
        self.id = id
        self.name = name
        self.token = ''

    def set_token(self, token):
        """
        Set the authentication token for the user
        """
        self.token = token
        return self

# set secret key for session encryption 
app = Flask(__name__)
app.secret_key = "and the cats in the cradle and the silver spoon"

app.config.from_object(__name__)

login_manager = LoginManager()

# set session protection to "strong" 
login_manager.session_protection = "strong"

# specify view function to handle login requests
login_manager.login_view = "login"

# set login message to be displayed when a user needs to log in to access a protected page
login_manager.login_message = u"Please log in to access this page."

# specify view function to handle reauthentication requests.
login_manager.refresh_view = "login"

# set message to be displayed when user needs to reauthenticate to access a protected page
login_manager.needs_refresh_message = (
    u"To protect your account, please reauthenticate to access this page."
)


# specify category of needs_refresh_message for styling or categorization
login_manager.needs_refresh_message_category = "info"



@login_manager.user_loader
def load_user(user_id):
    """
    load user object based on user ID.
    """
    return User(user_id, session['username']).set_token(session['token'])


login_manager.init_app(app)

login_manager.init_app(app)

@app.route("/")
@app.route("/index")
def index():
    """render index.html template for the homepage"""
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """handle registration form submission and process registration request"""
    form = RegistrationForm()

    if form.validate_on_submit():
        # retrieve entered username and password from the form
        username = request.form["username"]
        password = request.form["password"]

        # encrypt password using specified rounds and salt
        password = pwd_context.using(rounds=1122, salt='123hello').encrypt(password)

        # send registration request to server with username and encrypted password
        u = requests.post(f'http://restapi:5000/register?username={username}&password={password}').json()

        if u['message'] == 'Success':
            # display success message and redirect to login page
            flash(u"Success! Now try logging in")
            return redirect(url_for('login'))

        # display error message if user already exists in the database
        flash(u"User already exists in the database! Try picking a more unique username")

    # render registration form template with form object
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    """handle the login form submission and process the login request"""
    form = LoginForm()

    if form.validate_on_submit() and request.method == "POST" and "username" in request.form:
        # retrieve entered username and password from form
        username = request.form["username"]
        password = request.form["password"]

        # encrypt password using the specified rounds and salt
        password = pwd_context.using(rounds=1122, salt='123hello').encrypt(password)

        # send token request to the server with the username and encrypted password
        token = requests.get(f'http://restapi:5000/token?username={username}&password={password}').json()

        app.logger.debug(f'RESPONSE***  {token}')

        if not token['response'] == 'Failure':  # pwd_context.verify(password, hashed)
            # retrieve the remember option from the form
            remember = request.form.get("remember", "false") == "true"

            # store token and username in the session
            session["token"] = token['token']
            session["username"] = username

            # create a User object with the token and username
            user = User(token['id'], session['username']).set_token(session['token'])

            if login_user(user, remember=remember):
                # display success message and redirect to the next page or index
                flash("Logged in!")
                flash("I'll remember you") if remember else None

                next = request.args.get("next")
                if not is_safe_url(next):
                    abort(400)
                return redirect(next or url_for('index'))
            else:
                flash("Sorry, but you could not log in.")
        else:
            flash(u"Invalid username or password.")

    # render the login form template with the form object
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    """handle logout request and log out user"""
    logout_user()

    # display success message and redirect to the index page
    flash("Logged out.")
    return redirect(url_for("index"))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    # We will have an image
    # stegonograpy
    # hashing 
    
    # 1. hashing based on pixels
    # 2. send hash to server
    # 3. server gonna generate message with 
    #     - cdata = hash + username
    #     - pdata = username
    
    if request.method == 'POST':
        # check if the 'image' file was uploaded
        if 'image' in request.files:
            save_path = '/static/images/'
            if not os.path.exists(save_path):
                os.makedirs(save_path)

            image_file = request.files['image']
            img_path = os.path.join(save_path, image_file.filename)
            app.logger.debug(f"IMAGE PATH = {img_path}")
            
            # save image
            image_file.save(img_path)
            
            # generate hash
            img_hash = gen_hash(img_path)
            
            # get token from session
            headers = headers = {'Authorization': f'Bearer {session["token"]}'}
            response = requests.get(f'http://restapi:5000/genmessage?hash={img_hash}',
                               headers=headers).json()
            
            # convert to bytes string then to base 64 encoding
            msg = bytes.fromhex(response["message"])
            encrypted_message_b64 = base64.b64encode(msg)
            app.logger.debug(f"MESSAGE BEING EMBEDDED: {encrypted_message_b64}")
            
            # embed message
            encrypted_image = lsb.hide(img_path, encrypted_message_b64.decode())
            
            # save new image
            encrypted_img_path = os.path.join(save_path, "encrypted.png")
            encrypted_image.save(encrypted_img_path)
            app.logger.debug(f"IMAGE PATH = {encrypted_img_path}")
            # image_base64 = base64.b64encode(image).decode('utf-8')
            image_url = url_for('static', filename="encrypted.png")
            return render_template('image.html', image_url=image_url)
        
        # Return an error message if no 'image' file was uploaded
        flash("No image file found!")
    return render_template('upload.html')

@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    """
    - image with message is uploaded
    - remove encrypted message
    - send encrypted message and hash
    """
    if request.method == 'POST':
        app.logger.debug("line 189")
        # check if the 'image' file was uploaded
        if 'image' in request.files:
            image_file = request.files['image']
            save_path = 'templates/static/images/'
            if not os.path.exists(save_path):
                os.makedirs(save_path)

            image_file = request.files['image']
            img_path = os.path.join(save_path, image_file.filename)
            image_file.save(img_path)
            
            img_hash = gen_hash(img_path)
            
            # load image with hidden message
            try:
                app.logger.debug("line 205")
                image_with_hidden_message = lsb.reveal(img_path)
                
                
                # decode encrypted message from base64
                encrypted_message_decoded = base64.b64decode(image_with_hidden_message.encode())
                
                payload = {
                    "image_hash": img_hash,
                    "message": encrypted_message_decoded
                }
                app.logger.debug("line 216")
                response = requests.get(f'http://restapi:5000/verifymessage',
                        payload=payload).json()
                app.logger.debug("line 219")
                if response['message'] == 'Success':
                    owner = response['owner']
                    flash(f"The owner of this image is {owner}")
                else:
                    flash("No owner found for this image")
                return render_template('verify.html')
            except:
                flash("No message detected in image!")
                return render_template('upload.html')
        
        # Return an error message if no 'image' file was uploaded
        flash("No image file found!")
    return render_template('verify.html')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
