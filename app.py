# app.py

import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Flask uygulamamızı başlatıyoruz
app = Flask(__name__)

# --- UYGULAMA AYARLARI ---
# Bu ayarlar, web sitemizi yayınlayacağımız sunucudaki bilgilere göre çalışacak.
# os.environ.get komutu, sunucudaki "ortam değişkenlerini" okur. Bu, şifre gibi
# gizli bilgileri kodun içine yazmak yerine sunucuda saklamanın en güvenli yoludur.

# Güvenli oturumlar için gizli anahtar
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'varsayilan_gizli_anahtar_123')
# Veritabanı bağlantı adresi

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# PLC'den gelen veriyi doğrulamak için kullanacağımız API anahtarı
API_KEY = os.environ.get('API_KEY', 'GuvenliSifrem2025')

db_url = os.environ.get('DATABASE_URL')
if db_url:
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+pg8000://", 1)
    elif db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+pg8000://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url

# Veritabanı nesnesini ve Login yöneticisini oluşturuyoruz
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Giriş yapmayan kullanıcıyı bu sayfaya yönlendir

# --- VERİTABANI MODELLERİ (TABLOLARI) ---

# Kullanıcı bilgilerini tutacak olan User tablosu
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

# PLC'den gelen switch durumlarını tutacak olan ButonDurumu tablosu
class ButonDurumu(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buton_adi = db.Column(db.String(50), unique=True, nullable=False)
    durum = db.Column(db.Boolean, nullable=False)

# Flask-Login'in kullanıcıyı ID'sinden bulmasını sağlayan fonksiyon
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- WEB SAYFALARI ---

# Ana sayfa ('/') veya giriş sayfası ('/login')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.password == request.form['password']:
            login_user(user)
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Geçersiz kullanıcı adı veya şifre')
    return render_template('login.html')

# Verilerin gösterildiği ana ekran
@app.route('/dashboard')
@login_required # Bu satır sayesinde bu sayfayı sadece giriş yapmış kullanıcılar görebilir
def dashboard():
    butonlar = ButonDurumu.query.all()
    # dashboard.html dosyasına, 'switchler' değişkeni ile butonların listesini gönderiyoruz
    return render_template('dashboard.html', switchler=butonlar)

# Çıkış yapma
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Direkt site adresine girilince login'e yönlendir
@app.route('/')
def index():
    return redirect(url_for('login'))

# --- PLC'DEN VERİ ALMA ADRESİ (API) ---

@app.route('/api/update', methods=['POST'])
def api_update():
    # Güvenlik Kontrolü: plc_veri_gonderici.py'den gelen istekte doğru şifre var mı?
    if request.headers.get('X-API-KEY') != API_KEY:
        return jsonify({"hata": "Yetkisiz Erisim"}), 401
    
    gelen_veriler = request.get_json()
    if not gelen_veriler:
        return jsonify({"hata": "Gecersiz veri"}), 400

    # Gelen her bir veri için (switch1, switch2...)
    for buton_adi, durum in gelen_veriler.items():
        kayit = ButonDurumu.query.filter_by(buton_adi=buton_adi).first()
        if kayit: # Eğer bu switch veritabanında varsa, durumunu güncelle
            kayit.durum = durum
        else: # Yoksa, veritabanına yeni bir kayıt olarak ekle
            yeni_kayit = ButonDurumu(buton_adi=buton_adi, durum=durum)
            db.session.add(yeni_kayit)
    
    db.session.commit() # Değişiklikleri veritabanına kaydet
    return jsonify({"mesaj": "Veriler basariyla guncellendi"}), 200