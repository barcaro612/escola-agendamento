# -*- coding: utf-8 -*-
"""
Sistema de Agendamento de Aulas - Versão Final Corrigida (PythonAnywhere)
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import os
from flask_wtf.csrf import CSRFProtect

# Configuração do app
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)

# Configuração do banco de dados (SQLite - caminho absoluto para PythonAnywhere)
basedir = '/home/edsonbarcaro/escola-agendamento'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{basedir}/instance/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

# Garante que a pasta instance existe
os.makedirs(f'{basedir}/instance', exist_ok=True)

# Inicializações
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(100), nullable=False, default='')
    endereco = db.Column(db.String(200), nullable=False, default='')
    cpf = db.Column(db.String(14), nullable=False, default='00000000000')
    telefone = db.Column(db.String(15), nullable=False, default='')
    peso = db.Column(db.Float, nullable=False, default=0)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    tipo = db.Column(db.String(10), nullable=False, default='aluno')
    data_cadastro = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Modelo de Agendamento
class Agendamento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    aluno_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    instrutor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data = db.Column(db.String(10), nullable=False)
    periodo = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default='pendente')
    mensagem_instrutor = db.Column(db.Text)

    # Relacionamentos
    aluno_rel = db.relationship('User', foreign_keys=[aluno_id])
    instrutor_rel = db.relationship('User', foreign_keys=[instrutor_id])

# Context processor para adicionar 'now' a todos os templates
@app.context_processor
def inject_now():
    return {'now': datetime.now(timezone.utc)}

# =============================================
# ROTAS PRINCIPAIS
# =============================================
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_type'] = user.tipo
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Usuário ou senha incorretos', 'danger')
    return render_template('login.html')

# =============================================
# REDEFINIÇÃO DE SENHA (VALIDAÇÃO POR DADOS PESSOAIS)
# =============================================
@app.route('/esqueci-senha', methods=['GET', 'POST'])
def esqueci_senha():
    if request.method == 'POST':
        try:
            # Busca usuário pelos dados cadastrais
            user = db.session.execute(
                db.select(User).where(
                    User.nome_completo == request.form['nome_completo'],
                    User.cpf == request.form['cpf'],
                    User.peso == float(request.form['peso'])
                )
            ).scalar_one_or_none()

            if user:
                session['reset_user_id'] = user.id  # Armazena ID para redefinição
                return redirect(url_for('resetar_senha'))
            
            flash('Dados não encontrados. Verifique nome completo, CPF e peso.', 'danger')
        except ValueError:
            flash('Peso deve ser um número válido', 'danger')
    return render_template('esqueci_senha.html')

@app.route('/resetar-senha', methods=['GET', 'POST'])
def resetar_senha():
    if 'reset_user_id' not in session:
        return redirect(url_for('esqueci_senha'))

    if request.method == 'POST':
        if request.form['nova_senha'] != request.form['confirm_senha']:
            flash('As senhas não coincidem!', 'danger')
        else:
            user = db.session.get(User, session['reset_user_id'])
            user.password = generate_password_hash(request.form['nova_senha'])
            db.session.commit()
            session.pop('reset_user_id', None)
            flash('Senha redefinida com sucesso!', 'success')
            return redirect(url_for('login'))

    return render_template('resetar_senha.html')

# =============================================
# ROTAS EXISTENTES (PERMANECEM IGUAIS)
# =============================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            if request.form.get('password') != request.form.get('confirm_password'):
                flash('As senhas não coincidem', 'danger')
                return redirect(url_for('register'))

            tipo = request.form.get('tipo', 'aluno')
            if tipo == 'instrutor' and request.form.get('instrutor_key') != 'Yeshua':
                flash('Palavra-chave de instrutor incorreta', 'danger')
                return redirect(url_for('register'))

            new_user = User(
                nome_completo=request.form.get('nome_completo', ''),
                endereco=request.form.get('endereco', ''),
                cpf=request.form.get('cpf', '00000000000'),
                telefone=request.form.get('telefone', ''),
                peso=float(request.form.get('peso', 0)),
                username=request.form.get('username'),
                password=generate_password_hash(request.form.get('password')),
                tipo=tipo
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Cadastro realizado com sucesso!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro no cadastro: {str(e)}', 'danger')
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    
    if user.tipo == 'aluno':
        agendamentos = db.session.execute(
            db.select(Agendamento).where(Agendamento.aluno_id == user.id)
        ).scalars().all()
        return render_template('aluno_dashboard.html', user=user, agendamentos=agendamentos)
    else:
        agendamentos = db.session.execute(db.select(Agendamento)).scalars().all()
        usuarios = db.session.execute(db.select(User)).scalars().all()
        return render_template('instrutor_dashboard.html',
                            user=user,
                            agendamentos=agendamentos,
                            usuarios=usuarios)

# [...] (Todas as outras rotas permanecem EXATAMENTE IGUAIS)
# (visualizar_usuario, agendar, editar_agendamento, excluir_usuario, enviar_mensagem, logout)

# =============================================
# INICIALIZAÇÃO DO BANCO DE DADOS
# =============================================
def init_db():
    with app.app_context():
        db.create_all()
        
        if not db.session.execute(
            db.select(User).where(User.username == 'admin')
        ).scalar_one_or_none():
            admin = User(
                nome_completo='Administrador',
                endereco='N/A',
                cpf='00000000000',
                telefone='00000000000',
                peso=0,
                username='admin',
                password=generate_password_hash('admin123'),
                tipo='instrutor'
            )
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
