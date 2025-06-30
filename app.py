# app.py

import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Flask uygulamamızı başlatıyoruz
app = Flask(__name__)

# --- UYGULAMA AYARLARI ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'varsayilan_gizli_anahtar_123')

# Veritabanı bağlantı adresi için gelişmiş kontrol
db_url = os.environ.get('DATABASE_URL')
if db_url:
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+pg8000://", 1)
    elif db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+pg8000://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
API_KEY = os.environ.get('API_KEY', 'GuvenliSifrem2025')


# Veritabanı ve Login yöneticisi nesnelerini oluşturuyoruz
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# --- VERİTABANI MODELLERİ (TABLOLARI) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class ButonDurumu(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buton_adi = db.Column(db.String(50), unique=True, nullable=False)
    durum = db.Column(db.Boolean, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- WEB SAYFALARI ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.password == request.form['password']:
            login_user(user)
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Geçersiz kullanıcı adı veya şifre')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    butonlar = ButonDurumu.query.all()
    return render_template('dashboard.html', switchler=butonlar)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))


# --- PLC'DEN VERİ ALMA ADRESİ (API) ---
@app.route('/api/update', methods=['POST'])
def api_update():
    if request.headers.get('X-API-KEY') != API_KEY:
        return jsonify({"hata": "Yetkisiz Erisim"}), 401
    
    gelen_veriler = request.get_json()
    if not gelen_veriler:
        return jsonify({"hata": "Gecersiz veri"}), 400

    for buton_adi, durum in gelen_veriler.items():
        kayit = ButonDurumu.query.filter_by(buton_adi=buton_adi).first()
        if kayit:
            kayit.durum = durum
        else:
            yeni_kayit = ButonDurumu(buton_adi=buton_adi, durum=durum)
            db.session.add(yeni_kayit)
    
    db.session.commit()
    return jsonify({"mesaj": "Veriler basariyla guncellendi"}), 200

# --- Sadece bir kerelik kullanılacak KURULUM SAYFASI ---
@app.route('/setup')
def setup():
    try:
        # Veritabanı tablolarını oluşturur.
        with app.app_context():
            db.create_all()
            # Admin kullanıcısı var mı diye kontrol et.
            if not User.query.filter_by(username='admin').first():
                # Yoksa, oluştur.
                admin_user = User(username='admin', password='admin1234')
                db.session.add(admin_user)
                db.session.commit()
                return "KURULUM TAMAMLANDI! 'admin' kullanicisi olusturuldu. Simdi ana sayfaya gidip giris yapabilirsiniz."
            else:
                return "Kurulum zaten daha once yapilmis. 'admin' kullanicisi mevcut."
    except Exception as e:
        return f"Bir hata olustu: {str(e)}"