from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///comidas.db'
app.config["SECRET_KEY"] = "your_secret_key"
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    fullname = db.Column(db.String(150), nullable=False)

    def __init__(self, username, password, fullname):
        self.username = username
        self.password = generate_password_hash(password)
        self.fullname = fullname

class Comida(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    probada = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(username="admin", password="admin2025", fullname="Administrator")
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: username='admin', password='admin2025'")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")

@app.route('/')
@login_required
def index():
    comidas = Comida.query.all()
    return render_template('index.html', comidas=comidas)

@app.route('/agregar', methods=['POST'])
def agregar():
    nombre = request.form.get('nombre')
    if nombre:
        nueva_comida = Comida(nombre=nombre)
        db.session.add(nueva_comida)
        db.session.commit()
    return redirect(url_for('index'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return render_template("logout.html")

@app.route('/actualizar/<int:id>', methods=['POST'])
def actualizar(id):
    comida = Comida.query.get(id)
    if comida:
        comida.probada = not comida.probada
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/eliminar/<int:id>', methods=['POST'])
def eliminar(id):
    comida = Comida.query.get(id)
    if comida:
        db.session.delete(comida)
        db.session.commit()
    return redirect(url_for('index'))

@app.errorhandler(401)
def unauthorized_error(e):
    return redirect(url_for("login"))

@app.errorhandler(404)
def not_found_error(e):
    return render_template("error404.html")

@app.route('/cv')
def cv():
    return render_template('cv.html')

if __name__ == '__main__':
    app.run(debug=True)
