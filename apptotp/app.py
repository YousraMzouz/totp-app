from flask import *
from flask_bootstrap import Bootstrap
import os
import base64
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, UserMixin, logout_user,LoginManager ,  current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import *
import onetimepass
import pyqrcode

# Créer des instances de l'application 
app = Flask(__name__)
app.config.from_object('config')

# initialiser les extensions : 
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)


class User(UserMixin, db.Model):
    """Modèle d'utilisateur."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # générer un secret aléatoire : 
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('mot de passe non lisible')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


@lm.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    """Création de compte."""
    username = StringField('Nom d utilisateur', validators=[InputRequired(), Length(1, 64)])
    password = PasswordField('Mot de passe', validators=[InputRequired()])
    password_again = PasswordField('Confirmer le mot de passe ',
                                   validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """Connexion."""
    username = StringField('Username', validators=[InputRequired(), Length(1, 64)])
    password = PasswordField('Password', validators=[InputRequired()])
    token = StringField('Token', validators=[InputRequired(), Length(6, 6)])
    submit = SubmitField('Login')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """registration."""
    if current_user.is_authenticated:
        # Si l'utilisateur est connecté, pn passe
        return redirect(url_for('index'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Ce nom d utilisateur existe déjà.')
            return redirect(url_for('register'))
        # On ajoute l'utilisateur dans database 
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        # Redirection vers la page d'authentification à deux facteurs 
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)


@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
    
    # il faut s'assurer que le browser ne cache pas le qrcode
    
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # Pour une meilleure sécurité, on va enlever le nom d'utilisateur dans la session 
    del session['username']

   
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/login', methods=['GET', 'POST'])
def login():
   
    if current_user.is_authenticated:
        # s'il est connecté on passe 
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user.verify_password(form.password.data) or user is None or not user.verify_totp(form.token.data):
            flash(' Nom d utilisateur ou mot de passe incorrecte, vérifiez aussi le token. ')
            return redirect(url_for('login'))

        
        login_user(user)
        flash('Vous êtes connecté!')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
 
    logout_user()
    return redirect(url_for('index'))


# créer base de donées s'elle n'existe pas déjà:
db.create_all()


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
