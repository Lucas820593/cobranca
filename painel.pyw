# painel.py
# Painel Profissional — Sync Discord (database.json), Ngrok optional, CRUD assinaturas, users, webhook reminders
# Requisitos: pip install flask requests werkzeug pyngrok
# Uso: python painel.py

from flask import Flask, request, redirect, session, render_template_string, url_for
from functools import wraps
import json, os, logging, time, threading, shutil, re
from datetime import datetime, timedelta, date
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import quote as url_quote

# try import pyngrok (optional)
try:
    from pyngrok import ngrok, conf
    PYNGROK = True
    # CORREÇÃO 1: Configurar para não abrir console separado
    conf.get_default().monitor_thread = False
    conf.get_default().log_event_callback = None
    conf.get_default().log_format = None
    conf.get_default().heartbeat_interval = 30000  # 30 segundos
except Exception as e:
    ngrok = None
    conf = None
    PYNGROK = False
    print(f"Pyngrok not available: {e}")

# Importar subprocess para executar PowerShell (adicionei esta linha)
import subprocess

# ---------------------------
# Paths and files
# ---------------------------
BASE = os.path.dirname(__file__)
DB_FILE = os.path.join(BASE, "database.json")
CONFIG_FILE = os.path.join(BASE, "config.json")
LOG_FILE = os.path.join(BASE, "painel.log")
BACKUP_DIR = os.path.join(BASE, "backups")

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

# ---------------------------
# CORREÇÃO 2: Ngrok PowerShell starter (função nova)
# ---------------------------
def start_ngrok_via_powershell(port=3000):
    """
    Inicia o ngrok usando PowerShell para evitar abrir janela separada
    Retorna a URL pública se bem-sucedido, None se falhar
    """
    ngrok_path = r"C:\Users\lucas\AppData\Local\Programs\Python\Python311\Scripts\ngrok.exe"
    
    if not os.path.exists(ngrok_path):
        error_msg = f"❌ Ngrok não encontrado em: {ngrok_path}"
        logging.error(error_msg)
        print(error_msg)
        return None
    
    try:
        # Comando PowerShell para executar ngrok sem janela visível
        ps_command = f'''
        $ErrorActionPreference = 'Stop'
        try {{
            $processInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = "{ngrok_path}"
            $processInfo.Arguments = "http {port}"
            $processInfo.RedirectStandardError = $true
            $processInfo.RedirectStandardOutput = $true
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true
            $processInfo.WindowStyle = 'Hidden'
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $processInfo
            $process.Start() | Out-Null
            Start-Sleep -Seconds 2
            Write-Output $process.Id
        }} catch {{
            Write-Error "Falha ao iniciar ngrok: $_"
            exit 1
        }}
        '''
        
        # Executar PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=15,
            shell=True
        )
        
        if result.returncode != 0:
            error_msg = f"❌ Erro ao executar PowerShell: {result.stderr}"
            logging.error(error_msg)
            print(error_msg)
            return None
        
        if result.stdout.strip().isdigit():
            pid = int(result.stdout.strip())
            info_msg = f"✅ Ngrok iniciado via PowerShell (PID: {pid}) na porta {port}"
            logging.info(info_msg)
            print(info_msg)
            
            # Aguardar para ngrok estabilizar
            time.sleep(3)
            
            # Tentar obter URL pública via API ngrok
            try:
                response = requests.get("http://localhost:4040/api/tunnels", timeout=10)
                if response.status_code == 200:
                    tunnels = response.json().get("tunnels", [])
                    if tunnels:
                        public_url = tunnels[0].get("public_url")
                        success_msg = f"✅ Ngrok Public URL: {public_url}"
                        logging.info(success_msg)
                        print(success_msg)
                        return public_url
            except requests.exceptions.RequestException as e:
                warning_msg = f"⚠️  Não foi possível obter URL via API ngrok: {e}"
                logging.warning(warning_msg)
                print(warning_msg)
            
            # Tentar via pyngrok
            if PYNGROK:
                try:
                    tunnels = ngrok.get_tunnels()
                    if tunnels:
                        public_url = tunnels[0].public_url
                        success_msg = f"✅ Ngrok Public URL (via pyngrok): {public_url}"
                        logging.info(success_msg)
                        print(success_msg)
                        return public_url
                except Exception as e:
                    warning_msg = f"⚠️  Não foi possível obter URL via pyngrok: {e}"
                    logging.warning(warning_msg)
                    print(warning_msg)
            
            info_msg = "ℹ️  Ngrok iniciado mas URL não obtida automaticamente. Verifique em http://localhost:4040"
            logging.info(info_msg)
            print(info_msg)
            return "http://localhost:4040"
        else:
            error_msg = f"❌ Falha ao obter PID do ngrok: {result.stdout}"
            logging.error(error_msg)
            print(error_msg)
            return None
            
    except subprocess.TimeoutExpired:
        error_msg = "❌ Timeout ao iniciar ngrok via PowerShell"
        logging.error(error_msg)
        print(error_msg)
        return None
    except Exception as e:
        error_msg = f"❌ Erro inesperado ao iniciar ngrok: {e}"
        logging.error(error_msg)
        print(error_msg)
        return None

# ---------------------------
# Check if ngrok is already running (função nova)
# ---------------------------
def is_ngrok_running():
    """Verifica se ngrok já está em execução"""
    try:
        response = requests.get("http://localhost:4040/api/tunnels", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# ---------------------------
# Load config
# ---------------------------
def load_config():
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "bot_token": "",
            "channel_id": "",
            "webhook_url": "",
            "ngrok_token": "",
            "ngrok_region": "us",
            "ngrok_auth_token": "",
            "SECRET_KEY": "troque_esta_chave_por_uma_chave_segura",
            "session_timeout": 3600,
            "upload_on_change": True,
            "backup_interval_hours": 6,
            "max_backup_files": 10,
            "retry_attempts": 3,
            "retry_delay": 2,
            "enable_ngrok": False,
            "ngrok_subdomain": "",
            "auto_redirect_to_ngrok": True,
            "ngrok_domain": "ngrok-free.dev"
        }
        save_json(CONFIG_FILE, default_config)
        logging.warning("config.json created with defaults. Please edit it.")
        return default_config
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

cfg = load_config()
BOT_TOKEN = cfg.get("bot_token")
CHANNEL_ID = cfg.get("channel_id")
WEBHOOK_URL = cfg.get("webhook_url")
NGROK_TOKEN = cfg.get("ngrok_token") or cfg.get("ngrok_authtoken")
NGROK_REGION = cfg.get("ngrok_region", "us")
ENABLE_NGROK = cfg.get("enable_ngrok", False)
NGROK_SUBDOMAIN = cfg.get("ngrok_subdomain", "")
AUTO_REDIRECT_TO_NGROK = cfg.get("auto_redirect_to_ngrok", True)
NGROK_DOMAIN = cfg.get("ngrok_domain", "ngrok-free.dev")
SECRET_KEY = cfg.get("SECRET_KEY", "troque_esta_chave_por_uma_chave_segura")
SESSION_TIMEOUT = cfg.get("session_timeout", 3600)
UPLOAD_ON_CHANGE = cfg.get("upload_on_change", True)
BACKUP_INTERVAL_HOURS = cfg.get("backup_interval_hours", 6)
MAX_BACKUP_FILES = cfg.get("max_backup_files", 10)
RETRY_ATTEMPTS = cfg.get("retry_attempts", 3)
RETRY_DELAY = cfg.get("retry_delay", 2)

# ---------------------------
# Flask app
# ---------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(seconds=SESSION_TIMEOUT)

# ---------------------------
# JSON helpers
# ---------------------------
def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "settings" not in data:
                data["settings"] = default.get("settings", {
                    "created_at": datetime.now().isoformat(),
                    "last_backup": None,
                    "last_sync": None,
                    "last_modified": None
                })
            return data
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in {path}, using default")
        return default

def save_json(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if "settings" not in data:
            data["settings"] = {}
        data["settings"]["last_modified"] = datetime.now().isoformat()
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logging.error(f"Error saving JSON to {path}: {e}")
        return False

# ---------------------------
# Security validation helpers
# ---------------------------
def validate_username(username):
    """Valida nome de usuário seguro"""
    if not username or len(username) < 3 or len(username) > 50:
        return False
    pattern = r'^[A-Za-z0-9_\-\.]+$'
    return re.match(pattern, username) is not None

def validate_password(password):
    """Valida força da senha - AJUSTADO PARA 5 CARACTERES MINIMO"""
    if len(password) < 5:
        return False, "Senha deve ter pelo menos 5 caracteres"
    
    if len(password) > 100:
        return False, "Senha muito longa"
    
    return True, "Senha válida"

def validate_and_parse_date(date_str):
    """Valida e converte string para date object"""
    if not date_str:
        return None
    try:
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
            try:
                return datetime.strptime(date_str, fmt).date()
            except ValueError:
                continue
        raise ValueError(f"Formato de data inválido: {date_str}")
    except Exception as e:
        logging.error(f"Erro ao parse data {date_str}: {e}")
        raise

def validate_discord_id(discord_id):
    """Valida se é um ID do Discord válido"""
    if not discord_id:
        return False
    return discord_id.strip().isdigit()

# ---------------------------
# Backup management
# ---------------------------
def backup_database():
    """Cria backup do database atual"""
    if not os.path.exists(DB_FILE):
        return False
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"database_{timestamp}.json")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        shutil.copy2(DB_FILE, backup_path)
        logging.info(f"Backup criado: {backup_path}")
        
        if os.path.exists(BACKUP_DIR):
            files = sorted([f for f in os.listdir(BACKUP_DIR) 
                          if f.startswith("database_") and f.endswith(".json")])
            for old_file in files[:-MAX_BACKUP_FILES]:
                try:
                    os.remove(os.path.join(BACKUP_DIR, old_file))
                    logging.info(f"Backup antigo removido: {old_file}")
                except Exception as e:
                    logging.error(f"Erro ao remover backup {old_file}: {e}")
        return True
    except Exception as e:
        logging.error(f"Erro ao criar backup: {e}")
        return False

def save_with_backup(path, data):
    """Salva dados criando backup antes"""
    try:
        backup_database()
        return save_json(path, data)
    except Exception as e:
        logging.error(f"Erro em save_with_backup: {e}")
        return False

# ---------------------------
# Database initialization
# ---------------------------
def ensure_db():
    if not os.path.exists(DB_FILE):
        initial = {
            "users": [
                {
                    "username": "admin", 
                    "password_hash": generate_password_hash("admin"),
                    "role": "admin",
                    "created_at": datetime.now().isoformat(),
                    "is_super_admin": True
                }
            ],
            "clientes": [],
            "settings": {
                "created_at": datetime.now().isoformat(),
                "last_backup": None,
                "last_sync": None,
                "last_modified": None
            }
        }
        if save_json(DB_FILE, initial):
            logging.info("Created initial database.json with default admin/admin")
            backup_database()
        else:
            logging.error("Failed to create initial database")
    else:
        db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
        updated = False
        
        for user in db.get("users", []):
            if user.get("username") == "admin":
                if user.get("role") != "admin":
                    user["role"] = "admin"
                    user["is_super_admin"] = True
                    updated = True
                if not user.get("is_super_admin"):
                    user["is_super_admin"] = True
                    updated = True
        
        if updated:
            save_json(DB_FILE, db)

ensure_db()

# ---------------------------
# Audit logging
# ---------------------------
def log_action(username, action, details="", success=True):
    status = "SUCCESS" if success else "FAILED"
    log_msg = f"AUDIT - USER:{username} ACTION:{action} STATUS:{status}"
    if details:
        log_msg += f" DETAILS:{details}"
    logging.info(log_msg)

# ---------------------------
# Authentication decorators
# ---------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            if NGROK_PUBLIC_URL and AUTO_REDIRECT_TO_NGROK and request.host != NGROK_PUBLIC_URL.replace("https://", "").replace("http://", "").split("/")[0]:
                ngrok_login_url = f"{NGROK_PUBLIC_URL}/login"
                return redirect(ngrok_login_url)
            return redirect("/login")
        
        login_time = session.get("login_time")
        if login_time:
            try:
                login_dt = datetime.fromisoformat(login_time)
                if (datetime.now() - login_dt).seconds > SESSION_TIMEOUT:
                    log_action(session.get("username"), "session_expired", "", False)
                    session.clear()
                    return redirect("/login")
            except Exception:
                pass
        
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            if NGROK_PUBLIC_URL and AUTO_REDIRECT_TO_NGROK and request.host != NGROK_PUBLIC_URL.replace("https://", "").replace("http://", "").split("/")[0]:
                ngrok_login_url = f"{NGROK_PUBLIC_URL}/login"
                return redirect(ngrok_login_url)
            return redirect("/login")
        
        login_time = session.get("login_time")
        if login_time:
            try:
                login_dt = datetime.fromisoformat(login_time)
                if (datetime.now() - login_dt).seconds > SESSION_TIMEOUT:
                    log_action(session.get("username"), "session_expired", "", False)
                    session.clear()
                    return redirect("/login")
            except Exception:
                pass
        
        db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
        user = next((u for u in db.get("users", []) 
                    if u.get("username") == session.get("username")), None)
        
        if not user or (user.get("role") != "admin" and not user.get("is_super_admin")):
            log_action(session.get("username"), "admin_access_denied", 
                      f"tried to access {request.path}", False)
            return "Acesso negado: somente administradores", 403
        
        return f(*args, **kwargs)
    return decorated

# ---------------------------
# Discord helpers
# ---------------------------
DISCORD_API = "https://discord.com/api/v10"

def bot_headers():
    if not BOT_TOKEN:
        return {}
    return {"Authorization": f"Bot {BOT_TOKEN}"}

def get_bot_id():
    if not BOT_TOKEN:
        return None
    try:
        r = requests.get(f"{DISCORD_API}/users/@me", headers=bot_headers(), timeout=10)
        r.raise_for_status()
        return r.json().get("id")
    except Exception as e:
        logging.warning("get_bot_id failed: %s", e)
        return None

def download_db_from_discord_with_retry(filename="database.json"):
    for attempt in range(RETRY_ATTEMPTS):
        try:
            success = download_db_from_discord(filename)
            if success:
                return True
        except Exception as e:
            logging.warning(f"Download attempt {attempt + 1} failed: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY ** attempt)
    
    logging.error("All download attempts failed")
    return False

def download_db_from_discord(filename="database.json"):
    if not BOT_TOKEN or not CHANNEL_ID:
        logging.info("Bot token or channel id not configured — skipping download.")
        return False
    
    try:
        r = requests.get(
            f"{DISCORD_API}/channels/{CHANNEL_ID}/messages?limit=50", 
            headers=bot_headers(), 
            timeout=15
        )
        r.raise_for_status()
        msgs = r.json()
        
        for m in msgs:
            atts = m.get("attachments", [])
            for a in atts:
                fname = a.get("filename", "")
                if fname == filename or fname.lower().endswith(".json"):
                    url = a.get("url")
                    rr = requests.get(url, timeout=15)
                    rr.raise_for_status()
                    
                    if os.path.exists(DB_FILE):
                        backup_database()
                    
                    with open(DB_FILE, "wb") as fh:
                        fh.write(rr.content)
                    
                    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
                    
                    if "settings" not in db:
                        db["settings"] = {}
                    db["settings"]["last_sync"] = datetime.now().isoformat()
                    db["settings"]["downloaded_at"] = datetime.now().isoformat()
                    db["settings"]["downloaded_from"] = f"msg:{m.get('id')}"
                    
                    save_json(DB_FILE, db)
                    
                    logging.info("Downloaded %s from Discord (msg id=%s)", filename, m.get("id"))
                    return True
        
        logging.info("No %s attachment found in Discord channel.", filename)
        return False
    except Exception as e:
        logging.exception("download_db_from_discord error: %s", e)
        return False

def delete_old_db_messages(filename="database.json"):
    if not BOT_TOKEN or not CHANNEL_ID:
        return 0
    
    try:
        bot_id = get_bot_id()
        r = requests.get(
            f"{DISCORD_API}/channels/{CHANNEL_ID}/messages?limit=50", 
            headers=bot_headers(), 
            timeout=15
        )
        r.raise_for_status()
        msgs = r.json()
        
        deleted = 0
        for m in msgs:
            for a in m.get("attachments", []):
                fname = a.get("filename", "")
                if fname == filename or fname.lower().endswith(".json"):
                    author = m.get("author", {}).get("id")
                    if bot_id and author != bot_id:
                        continue
                    try:
                        d = requests.delete(
                            f"{DISCORD_API}/channels/{CHANNEL_ID}/messages/{m.get('id')}", 
                            headers=bot_headers(), 
                            timeout=10
                        )
                        if d.status_code in (200, 204):
                            deleted += 1
                    except Exception:
                        pass
        
        logging.info("Deleted %d old DB messages (if any).", deleted)
        return deleted
    except Exception as e:
        logging.exception("delete_old_db_messages error: %s", e)
        return 0

def upload_db_to_discord_with_retry(path=DB_FILE, filename="database.json", content_message="database update", uploaded_by="system"):
    for attempt in range(RETRY_ATTEMPTS):
        try:
            success = upload_db_to_discord(path, filename, content_message, uploaded_by)
            if success:
                return True
        except Exception as e:
            logging.warning(f"Upload attempt {attempt + 1} failed: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY ** attempt)
    
    logging.error("All upload attempts failed")
    return False

def upload_db_to_discord(path=DB_FILE, filename="database.json", content_message="database update", uploaded_by="system"):
    if not BOT_TOKEN or not CHANNEL_ID:
        logging.info("Bot token or channel id not configured — skipping upload.")
        return False
    
    try:
        delete_old_db_messages(filename)
        
        url = f"{DISCORD_API}/channels/{CHANNEL_ID}/messages"
        
        with open(path, "rb") as fh:
            files = {"file": (filename, fh, "application/json")}
            data = {"content": content_message}
            r = requests.post(url, headers=bot_headers(), files=files, data=data, timeout=30)
            r.raise_for_status()
        
        db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
        
        if "settings" not in db:
            db["settings"] = {}
        
        db["settings"]["last_sync"] = datetime.now().isoformat()
        db["settings"]["last_upload"] = datetime.now().isoformat()
        db["settings"]["uploaded_by"] = uploaded_by
        
        save_json(DB_FILE, db)
        
        logging.info("Uploaded DB to Discord channel.")
        return True
    except Exception as e:
        logging.exception("upload_db_to_discord error: %s", e)
        return False

# ---------------------------
# Business logic
# ---------------------------
def build_message_profissional(cliente):
    nome = cliente.get("nome", "—")
    cid = cliente.get("id", "")
    produto = cliente.get("produto", "—")
    preco = cliente.get("preco", "—")
    data_compra = cliente.get("data_compra", "—")
    next_renewal = cliente.get("next_renewal", "—")
    dias = "-"
    
    # Verificar se é lifetime
    if cliente.get("lifetime"):
        embed = {
            "title": "💰 Cobrança Automática - PLANO LIFETIME",
            "color": 5025616,  # Verde
            "fields": [
                {
                    "name": "👤 Cliente",
                    "value": f"{nome}\n<@{cid}>",
                    "inline": True
                },
                {
                    "name": "📦 Produto",
                    "value": produto,
                    "inline": True
                },
                {
                    "name": "💲 Preço",
                    "value": preco if preco else "—",
                    "inline": True
                },
                {
                    "name": "📅 Informações",
                    "value": f"**Data da compra:** {data_compra}\n**Plano:** VITALÍCIO\n**Status:** Ativo permanentemente"
                }
            ],
            "footer": {"text": "Sistema de Gestão - Plano Lifetime"},
            "timestamp": datetime.utcnow().isoformat()
        }
        return embed
    
    try:
        if next_renewal:
            d = datetime.fromisoformat(next_renewal).date()
            diff = (d - date.today()).days
            dias = f"{diff} dias" if diff >= 0 else "0 dias"
            color = 5025616 if diff > 7 else 16753920 if diff > 0 else 16711680  # Verde > Amarelo > Vermelho
    except Exception:
        dias = "-"
        color = 10197915  # Cinza
    
    embed = {
        "title": "💰 Cobrança Automática",
        "color": color,
        "fields": [
            {
                "name": "👤 Cliente",
                "value": f"{nome}\n<@{cid}>",
                "inline": True
            },
            {
                "name": "📦 Produto",
                "value": produto,
                "inline": True
            },
            {
                "name": "💲 Preço",
                "value": preco if preco else "—",
                "inline": True
            },
            {
                "name": "🛒 Data da compra",
                "value": data_compra,
                "inline": True
            },
            {
                "name": "📅 Renovação em",
                "value": next_renewal,
                "inline": True
            },
            {
                "name": "⏳ Dias Restantes",
                "value": dias,
                "inline": True
            }
        ],
        "footer": {"text": "Sistema de Gestão - Renovação Automática"},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if cliente.get("paused"):
        embed["color"] = 8421504  # Cinza escuro
        embed["title"] = "⏸️ Assinatura Pausada"
        embed["fields"].append({
            "name": "⚠️ Status",
            "value": "Assinatura temporariamente pausada",
            "inline": False
        })
    
    return embed

def send_webhook(content=None, embeds=None):
    if not WEBHOOK_URL:
        logging.warning("Webhook URL not configured.")
        return False
    
    try:
        payload = {}
        
        if content:
            payload["content"] = content
        
        if embeds:
            payload["embeds"] = embeds
        
        if not payload:
            logging.warning("No content or embeds provided for webhook.")
            return False
        
        r = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        r.raise_for_status()
        logging.info("Webhook sent successfully.")
        return True
    except Exception as e:
        logging.exception("send_webhook error: %s", e)
        return False

def send_webhook_with_retry(content=None, embeds=None, max_retries=3):
    for attempt in range(max_retries):
        try:
            success = send_webhook(content, embeds)
            if success:
                return True
        except Exception as e:
            logging.warning(f"Webhook attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
    return False

# ---------------------------
# Workers
# ---------------------------
STOP_EVENT = threading.Event()
WORKER_ERROR_COUNT = 0
MAX_WORKER_ERRORS = 10

def renewals_worker(interval_seconds=60):
    global WORKER_ERROR_COUNT
    logging.info("Renewals worker starting (interval %ds)...", interval_seconds)
    
    while not STOP_EVENT.is_set():
        try:
            db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
            changed = False
            today = date.today()
            today_iso = today.isoformat()
            tomorrow_iso = (today + timedelta(days=1)).isoformat()
            
            for c in db.get("clientes", []):
                if c.get("paused"):
                    continue
                
                # Pular clientes lifetime
                if c.get("lifetime"):
                    continue
                
                nr = c.get("next_renewal")
                if not nr:
                    continue
                
                if nr == tomorrow_iso:
                    if c.get("last_notified_date") != f"before:{tomorrow_iso}":
                        embed = build_message_profissional(c)
                        # Modificar embed para notificação de 1 dia
                        embed["title"] = "⏰ LEMBRETE - 1 DIA PARA RENOVAÇÃO"
                        embed["color"] = 16753920  # Amarelo/laranja
                        
                        ok = send_webhook_with_retry(embeds=[embed])
                        if ok:
                            c["last_notified_date"] = f"before:{tomorrow_iso}"
                            changed = True
                            logging.info("Sent '1 day before' reminder for %s", c.get("nome"))
                
                if nr == today_iso:
                    if c.get("last_notified_date") != f"on:{today_iso}":
                        embed = build_message_profissional(c)
                        # Modificar embed para notificação do dia
                        embed["title"] = "🔔 RENOVAÇÃO HOJE"
                        embed["color"] = 16711680  # Vermelho
                        
                        ok = send_webhook_with_retry(embeds=[embed])
                        if ok:
                            c["last_notified_date"] = f"on:{today_iso}"
                            changed = True
                            logging.info("Sent 'on day' reminder for %s", c.get("nome"))
            
            if changed:
                if save_with_backup(DB_FILE, db):
                    if UPLOAD_ON_CHANGE and BOT_TOKEN and CHANNEL_ID:
                        upload_db_to_discord_with_retry(
                            DB_FILE, 
                            content_message="auto-update after notification",
                            uploaded_by="system"
                        )
            
            WORKER_ERROR_COUNT = 0
            
        except Exception as e:
            logging.exception("renewals_worker error: %s", e)
            WORKER_ERROR_COUNT += 1
            
            if WORKER_ERROR_COUNT >= MAX_WORKER_ERRORS:
                logging.error("Too many worker errors, pausing for 1 hour")
                time.sleep(3600)
                WORKER_ERROR_COUNT = 0
        
        for _ in range(int(interval_seconds)):
            if STOP_EVENT.is_set():
                break
            time.sleep(1)
    
    logging.info("Renewals worker stopped.")

def backup_periodic_worker():
    logging.info("Backup periodic worker starting...")
    
    while not STOP_EVENT.is_set():
        try:
            if backup_database():
                if UPLOAD_ON_CHANGE and BOT_TOKEN and CHANNEL_ID:
                    upload_db_to_discord_with_retry(
                        DB_FILE, 
                        content_message=f"backup auto {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                        uploaded_by="system"
                    )
                
                db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
                if "settings" not in db:
                    db["settings"] = {}
                db["settings"]["last_backup"] = datetime.now().isoformat()
                save_json(DB_FILE, db)
                
                logging.info("Backup periódico realizado com sucesso")
            
        except Exception as e:
            logging.error(f"Backup periódico falhou: {e}")
        
        sleep_seconds = BACKUP_INTERVAL_HOURS * 3600
        for _ in range(sleep_seconds):
            if STOP_EVENT.is_set():
                break
            time.sleep(1)
    
    logging.info("Backup periodic worker stopped.")

# ---------------------------
# Templates (mantive todos os templates IDÊNTICOS aos seus)
# ---------------------------

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel Admin - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); color: #f8fafc; min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .login-container { width: 100%; max-width: 400px; background: rgba(30, 41, 59, 0.8); backdrop-filter: blur(10px); border-radius: 16px; border: 1px solid rgba(148, 163, 184, 0.1); box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3); overflow: hidden; }
        .login-header { padding: 32px 32px 24px; text-align: center; border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
        .logo { display: flex; align-items: center; justify-content: center; gap: 12px; margin-bottom: 16px; }
        .logo-icon { width: 40px; height: 40px; background: linear-gradient(135deg, #7c3aed, #8b5cf6); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 20px; }
        .logo-text { font-size: 24px; font-weight: 700; background: linear-gradient(135deg, #7c3aed, #8b5cf6); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .login-subtitle { color: #94a3b8; font-size: 14px; margin-top: 4px; }
        .login-form { padding: 32px; }
        .form-group { margin-bottom: 20px; }
        .form-label { display: block; margin-bottom: 8px; font-weight: 500; font-size: 14px; color: #94a3b8; }
        .form-input { width: 100%; padding: 14px 16px; background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 12px; color: #f8fafc; font-size: 15px; transition: all 0.2s ease; }
        .form-input:focus { outline: none; border-color: #7c3aed; box-shadow: 0 0 0 3px rgba(124, 58, 237, 0.15); background: rgba(15, 23, 42, 0.8); }
        .form-input::placeholder { color: #64748b; }
        .password-container { position: relative; }
        .toggle-password { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); background: none; border: none; color: #94a3b8; cursor: pointer; padding: 4px; }
        .login-button { width: 100%; padding: 14px; background: linear-gradient(135deg, #7c3aed, #8b5cf6); color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.2s ease; margin-top: 8px; }
        .login-button:hover { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(124, 58, 237, 0.3); }
        .login-button:active { transform: translateY(0); }
        .error-message { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: #ef4444; padding: 12px 16px; border-radius: 12px; margin-top: 16px; font-size: 14px; display: flex; align-items: center; gap: 10px; }
        .error-icon { font-size: 18px; }
        .login-footer { text-align: center; padding: 20px; border-top: 1px solid rgba(148, 163, 184, 0.1); font-size: 12px; color: #64748b; }
        @media (max-width: 480px) { .login-container { border-radius: 12px; } .login-header, .login-form { padding: 24px; } }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const togglePassword = document.querySelector('.toggle-password');
            const passwordInput = document.querySelector('input[name="password"]');
            if (togglePassword && passwordInput) {
                togglePassword.addEventListener('click', function() {
                    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                    passwordInput.setAttribute('type', type);
                    this.textContent = type === 'password' ? '👁️' : '👁️‍🗨️';
                });
            }
            const loginForm = document.querySelector('form');
            if (loginForm) {
                loginForm.addEventListener('submit', function() {
                    const submitButton = this.querySelector('button[type="submit"]');
                    if (submitButton) {
                        submitButton.disabled = true;
                        submitButton.innerHTML = 'Entrando...';
                    }
                });
            }
            const usernameInput = document.querySelector('input[name="username"]');
            if (usernameInput) { usernameInput.focus(); }
        });
    </script>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <div class="logo">
                <div class="logo-icon">🔒</div>
                <div class="logo-text">Painel Admin</div>
            </div>
            <div class="login-subtitle">Área restrita</div>
        </div>
        <form method="post" class="login-form" autocomplete="on">
            <div class="form-group">
                <label for="username" class="form-label">Usuário</label>
                <input type="text" id="username" name="username" class="form-input" placeholder="Digite seu usuário" required autocomplete="username" minlength="3" maxlength="50">
            </div>
            <div class="form-group">
                <label for="password" class="form-label">Senha</label>
                <div class="password-container">
                    <input type="password" id="password" name="password" class="form-input" placeholder="Digite sua senha" required autocomplete="current-password" minlength="5" maxlength="100">
                    <button type="button" class="toggle-password" aria-label="Mostrar senha">👁️</button>
                </div>
            </div>
            <button type="submit" class="login-button">Entrar</button>
            {% if error %}
            <div class="error-message">
                <span class="error-icon">⚠️</span>
                <span>{{ error }}</span>
            </div>
            {% endif %}
        </form>
        <div class="login-footer">Sistema de gestão • Acesso restrito</div>
    </div>
</body>
</html>
"""

MAIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel - Assinaturas</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; }
        .sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 220px; background: #1e293b; padding: 20px; overflow-y: auto; }
        .sidebar h2 { color: #7c3aed; margin-bottom: 20px; font-size: 20px; }
        .sidebar a { display: block; color: #94a3b8; padding: 10px 0; text-decoration: none; border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
        .sidebar a:hover { color: #7c3aed; }
        .container { margin-left: 240px; padding: 30px; }
        @media (max-width: 768px) { .sidebar { position: relative; width: 100%; height: auto; } .container { margin-left: 0; } }
        .card { background: #1e293b; padding: 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid rgba(148, 163, 184, 0.1); }
        .filters-card { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 20px; }
        .filter-group { display: flex; gap: 10px; align-items: center; }
        .form-row { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 15px; }
        input, select, button { padding: 12px; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.1); background: #0f172a; color: #f8fafc; flex: 1; min-width: 200px; }
        select { cursor: pointer; }
        button { padding: 12px 20px; border-radius: 8px; border: none; background: #7c3aed; color: white; cursor: pointer; font-weight: 600; }
        button:hover { background: #6b4ce6; }
        .small { color: #94a3b8; font-size: 13px; margin-top: 10px; }
        .paused { opacity: 0.6; }
        .danger { background: #ef4444 !important; }
        .danger:hover { background: #dc2626 !important; }
        .success { background: #10b981 !important; }
        .success:hover { background: #0da271 !important; }
        .renew { background: #f59e0b !important; }
        .renew:hover { background: #d97706 !important; }
        .alert { background: #f59e0b; color: #000; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .client-actions { margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap; }
        .lifetime-badge { background: #10b981; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin-left: 8px; }
        .expired { color: #ef4444; font-weight: bold; }
        .filter-button { background: #475569; }
        .filter-button:hover { background: #64748b; }
        .active-filter { background: #7c3aed !important; }
        .stats { display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }
        .stat-card { background: #1e293b; padding: 15px; border-radius: 10px; border: 1px solid rgba(148, 163, 184, 0.1); flex: 1; min-width: 150px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #7c3aed; }
        .stat-label { font-size: 12px; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>Painel</h2>
        <a href="/">Assinaturas</a>
        <a href="/test">Testar Webhook</a>
        <a href="/users">Gerenciar Usuários</a>
        <a href="/backup">Backup & Restore</a>
        <a href="/logs">Logs de Acesso</a>
        <a href="/logout">Sair</a>
    </div>
    <div class="container">
        <h1>Assinaturas</h1>
        {% if message %}<div class="alert">{{ message }}</div>{% endif %}
        
        <!-- Estatísticas -->
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{ stats.total }}</div>
                <div class="stat-label">Total Clientes</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.mensal }}</div>
                <div class="stat-label">Planos Mensais</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.lifetime }}</div>
                <div class="stat-label">Planos Lifetime</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.paused }}</div>
                <div class="stat-label">Pausados</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.expired }}</div>
                <div class="stat-label">Expirados</div>
            </div>
        </div>
        
        <!-- Filtros e Ordenação -->
        <div class="card filters-card">
            <div class="filter-group">
                <strong>Filtrar:</strong>
                <a href="/?filter=all&sort={{ sort }}&order={{ order }}" class="filter-button {% if filter == 'all' %}active-filter{% endif %}" style="padding: 8px 12px; border-radius: 6px; text-decoration: none;">Todos</a>
                <a href="/?filter=mensal&sort={{ sort }}&order={{ order }}" class="filter-button {% if filter == 'mensal' %}active-filter{% endif %}" style="padding: 8px 12px; border-radius: 6px; text-decoration: none;">Mensais</a>
                <a href="/?filter=lifetime&sort={{ sort }}&order={{ order }}" class="filter-button {% if filter == 'lifetime' %}active-filter{% endif %}" style="padding: 8px 12px; border-radius: 6px; text-decoration: none;">Lifetime</a>
                <a href="/?filter=expired&sort={{ sort }}&order={{ order }}" class="filter-button {% if filter == 'expired' %}active-filter{% endif %}" style="padding: 8px 12px; border-radius: 6px; text-decoration: none;">Expirados</a>
                <a href="/?filter=active&sort={{ sort }}&order={{ order }}" class="filter-button {% if filter == 'active' %}active-filter{% endif %}" style="padding: 8px 12px; border-radius: 6px; text-decoration: none;">Ativos</a>
                <a href="/?filter=paused&sort={{ sort }}&order={{ order }}" class="filter-button {% if filter == 'paused' %}active-filter{% endif %}" style="padding: 8px 12px; border-radius: 6px; text-decoration: none;">Pausados</a>
            </div>
            <div class="filter-group" style="margin-top: 10px;">
                <strong>Ordenar por:</strong>
                <select onchange="window.location.href='/?filter={{ filter }}&sort='+this.value+'&order={{ order }}'" style="width: auto;">
                    <option value="nome" {% if sort == 'nome' %}selected{% endif %}>Nome</option>
                    <option value="renovacao" {% if sort == 'renovacao' %}selected{% endif %}>Data Renovação</option>
                    <option value="compra" {% if sort == 'compra' %}selected{% endif %}>Data Compra</option>
                    <option value="dias" {% if sort == 'dias' %}selected{% endif %}>Dias Restantes</option>
                </select>
                <select onchange="window.location.href='/?filter={{ filter }}&sort={{ sort }}&order='+this.value" style="width: auto;">
                    <option value="asc" {% if order == 'asc' %}selected{% endif %}>Crescente (A-Z)</option>
                    <option value="desc" {% if order == 'desc' %}selected{% endif %}>Decrescente (Z-A)</option>
                </select>
            </div>
        </div>
        
        <div class="card">
            <h3>Adicionar Assinatura</h3>
            <form method="post" action="/add">
                <div class="form-row">
                    <input name="nome" placeholder="Nome" required maxlength="100">
                    <input name="id" placeholder="Discord ID (somente números)" required pattern="[0-9]+" title="Somente números">
                </div>
                <div class="form-row">
                    <input name="produto" placeholder="Produto" required maxlength="100">
                    <input name="preco" placeholder="Preço (opcional)" maxlength="50">
                    <input type="date" name="data_compra" required>
                </div>
                <div class="form-row">
                    <select name="tipo_plano" style="flex: 1; padding: 12px; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.1); background: #0f172a; color: #f8fafc;">
                        <option value="mensal">Plano Mensal (30 dias)</option>
                        <option value="lifetime">Plano Lifetime (Vitalício)</option>
                    </select>
                </div>
                <button type="submit">Adicionar</button>
                <p class="small">Para plano mensal: próxima renovação = data da compra + 30 dias</p>
            </form>
        </div>
        
        {% for c in clientes %}
        <div class="card {% if c.get('paused') %}paused{% endif %}">
            <b>{{ c.get('nome')|e }}</b> 
            <span class="small">ID: {{ c.get('id')|e }}</span>
            {% if c.get('lifetime') %}
            <span class="lifetime-badge">LIFETIME</span>
            {% endif %}
            <br>
            Produto: {{ c.get('produto')|e }}<br>
            Compra: {{ c.get('data_compra')|e }} 
            {% if c.get('lifetime') %}
            — <span style="color: #10b981; font-weight: bold;">VITALÍCIO</span>
            {% else %}
            — Renovação: {{ c.get('next_renewal')|e }} — 
            <span class="{% if c.get('dias_num') < 0 %}expired{% endif %}">
                Dias restantes: {{ c.get('dias')|e }}
            </span>
            {% endif %}
            <br>
            <div class="client-actions">
                <form method="get" action="/edit/{{ c.get('id')|e }}"><button type="submit">✏ Editar</button></form>
                {% if not c.get('lifetime') %}
                <form method="post" action="/renew/{{ c.get('id')|e }}" onsubmit="return confirm('Renovar assinatura por mais 30 dias?');">
                    <button type="submit" class="renew" title="Adicionar 30 dias à data de renovação">🔄 Renovar</button>
                </form>
                {% endif %}
                {% if c.get('paused') %}
                <form method="post" action="/resume/{{ c.get('id')|e }}"><button type="submit" class="success">▶ Retomar</button></form>
                {% else %}
                <form method="post" action="/pause/{{ c.get('id')|e }}"><button type="submit">⏸ Pausar</button></form>
                {% endif %}
                <form method="post" action="/delete/{{ c.get('id')|e }}" onsubmit="return confirm('Tem certeza que deseja excluir esta assinatura?');">
                    <button type="submit" class="danger">🗑 Excluir</button>
                </form>
            </div>
        </div>
        {% else %}
        <div class="card"><p>Nenhuma assinatura encontrada com os filtros atuais.</p></div>
        {% endfor %}
    </div>
</body>
</html>
"""

TEST_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Testar Webhook</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }
        select, input, button { padding: 12px; border-radius: 8px; border: none; box-sizing: border-box; width: 100%; margin-bottom: 15px; }
        button { background: #7c3aed; color: white; cursor: pointer; font-weight: 600; }
        button:hover { background: #6b4ce6; }
        a { color: #7c3aed; text-decoration: none; }
        .alert { background: #10b981; color: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .error { background: #ef4444; color: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
    </style>
</head>
<body>
    <h2>Testar Webhook</h2>
    {% if message %}<div class="alert">{{ message }}</div>{% elif error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="post" action="/test_send">
        <select name="idx">
            {% for c in clientes %}<option value="{{ loop.index0 }}">{{ c.get('nome')|e }} — {{ c.get('produto')|e }}</option>{% endfor %}
        </select>
        <button type="submit">Enviar Teste</button>
    </form>
    <p><a href="/">← Voltar</a></p>
</body>
</html>
"""

EDIT_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Editar Assinatura</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }
        input, select, button { padding: 12px; border-radius: 8px; border: none; margin: 8px 0; width: 100%; box-sizing: border-box; }
        select { border: 1px solid rgba(148, 163, 184, 0.1); background: #0f172a; color: #f8fafc; }
        button { background: #7c3aed; color: white; cursor: pointer; font-weight: 600; }
        button:hover { background: #6b4ce6; }
        a { color: #7c3aed; text-decoration: none; }
    </style>
</head>
<body>
    <h2>Editar Assinatura</h2>
    <form method="post">
        <input name="nome" value="{{ c.get('nome')|e }}" required maxlength="100">
        <input name="id" value="{{ c.get('id')|e }}" required pattern="[0-9]+" title="Somente números">
        <input name="produto" value="{{ c.get('produto')|e }}" required maxlength="100">
        <input name="preco" value="{{ c.get('preco','')|e }}" maxlength="50">
        <input type="date" name="data_compra" value="{{ c.get('data_compra')|e }}" required>
        <select name="tipo_plano">
            <option value="mensal" {% if not c.get('lifetime') %}selected{% endif %}>Plano Mensal (30 dias)</option>
            <option value="lifetime" {% if c.get('lifetime') %}selected{% endif %}>Plano Lifetime (Vitalício)</option>
        </select>
        <button type="submit">Salvar</button>
    </form>
    <p><a href="/">← Voltar</a></p>
</body>
</html>
"""

USERS_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gerenciar Usuários</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }
        input, button, select { padding: 12px; border-radius: 8px; border: none; margin: 8px 0; box-sizing: border-box; }
        button { background: #7c3aed; color: white; cursor: pointer; font-weight: 600; }
        button:hover { background: #6b4ce6; }
        .danger { background: #ef4444 !important; }
        .danger:hover { background: #dc2626 !important; }
        a { color: #7c3aed; text-decoration: none; }
        ul { list-style: none; padding: 0; }
        li { padding: 15px; background: #1e293b; margin: 10px 0; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.1); }
        .alert { background: #10b981; color: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .error { background: #ef4444; color: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
    </style>
</head>
<body>
    <h2>Gerenciar Usuários</h2>
    {% if message %}<div class="alert">{{ message }}</div>{% elif error %}<div class="error">{{ error }}</div>{% endif %}
    <h3>Criar Usuário</h3>
    <form method="post" action="/add_user">
        <input name="username" placeholder="Usuário" required maxlength="50">
        <input name="password" placeholder="Senha" required minlength="5">
        <select name="role" style="width: 100%; margin: 8px 0;">
            <option value="user">Usuário</option>
            <option value="admin">Administrador</option>
        </select>
        <button type="submit">Criar Usuário</button>
    </form>
    <h3>Usuários do Sistema</h3>
    <ul>
        {% for u in users %}
        <li>
            <strong>{{ u.get('username')|e }}</strong> ({{ u.get('role')|e }})<br>
            <small>Criado em: {{ u.get('created_at', 'N/A')|e }}</small>
            <form method="post" action="/del_user" style="display: inline;">
                <input type="hidden" name="username" value="{{ u.get('username')|e }}">
                <button type="submit" class="danger" onclick="return confirm('Remover usuário {{ u.get('username')|e }}?')">Remover</button>
            </form>
            <form method="post" action="/change_password" style="display: inline;">
                <input type="hidden" name="username" value="{{ u.get('username')|e }}">
                <input name="newpass" placeholder="Nova senha" minlength="5" style="width: 200px;">
                <button type="submit">Alterar senha</button>
            </form>
        </li>
        {% else %}<li>Nenhum usuário cadastrado.</li>{% endfor %}
    </ul>
    <p><a href="/">← Voltar ao Painel</a></p>
</body>
</html>
"""

BACKUP_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup & Restore</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }
        button, input { padding: 12px; border-radius: 8px; border: none; margin: 8px; box-sizing: border-box; }
        button { background: #7c3aed; color: white; cursor: pointer; font-weight: 600; }
        button:hover { background: #6b4ce6; }
        .danger { background: #ef4444 !important; }
        .success { background: #10b981 !important; }
        a { color: #7c3aed; text-decoration: none; }
        .card { background: #1e293b; padding: 20px; border-radius: 12px; margin: 20px 0; border: 1px solid rgba(148, 163, 184, 0.1); }
        .info { color: #94a3b8; font-size: 13px; margin-top: 10px; }
        .alert { background: #10b981; color: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .error { background: #ef4444; color: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
    </style>
</head>
<body>
    <h2>Backup & Restore</h2>
    {% if message %}<div class="alert">{{ message }}</div>{% elif error %}<div class="error">{{ error }}</div>{% endif %}
    <div class="card">
        <h3>Sincronização Manual</h3>
        <form method="post" action="/sync_discord"><button type="submit">⬇ Baixar do Discord</button></form>
        <p class="info">Baixa o arquivo mais recente do canal do Discord</p>
        <form method="post" action="/upload_discord"><button type="submit" class="success">⬆ Upload para Discord</button></form>
        <p class="info">Envia o arquivo local para o Discord (sobrescreve anterior)</p>
    </div>
    <div class="card">
        <h3>Backup Local</h3>
        <form method="post" action="/create_backup"><button type="submit" class="success">💾 Criar Backup Local</button></form>
        <p class="info">Cria um backup local no diretório backups/</p>
        {% if backups %}
        <h4>Backups Disponíveis:</h4>
        <ul>
            {% for backup in backups %}
            <li style="margin: 10px 0; padding: 10px; background: #0f172a; border-radius: 8px;">
                {{ backup.filename }} ({{ backup.size }})
                <form method="post" action="/restore_backup" style="display: inline;">
                    <input type="hidden" name="filename" value="{{ backup.filename }}">
                    <button type="submit" onclick="return confirm('Restaurar backup {{ backup.filename }}?')">↻ Restaurar</button>
                </form>
                <form method="post" action="/delete_backup" style="display: inline;">
                    <input type="hidden" name="filename" value="{{ backup.filename }}">
                    <button type="submit" class="danger" onclick="return confirm('Excluir backup {{ backup.filename }}?')">🗑 Excluir</button>
                </form>
            </li>
            {% endfor %}
        </ul>
        {% else %}<p>Nenhum backup local encontrado.</p>{% endif %}
        <p class="info">Backups automáticos a cada {{ backup_interval }} horas.</p>
    </div>
    <p><a href="/">← Voltar ao Painel</a></p>
</body>
</html>
"""

LOGS_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logs de Acesso</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; }
        .sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 220px; background: #1e293b; padding: 20px; overflow-y: auto; }
        .sidebar h2 { color: #7c3aed; margin-bottom: 20px; font-size: 20px; }
        .sidebar a { display: block; color: #94a3b8; padding: 10px 0; text-decoration: none; border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
        .sidebar a:hover { color: #7c3aed; }
        .container { margin-left: 240px; padding: 30px; }
        @media (max-width: 768px) { .sidebar { position: relative; width: 100%; height: auto; } .container { margin-left: 0; } }
        .card { background: #1e293b; padding: 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid rgba(148, 163, 184, 0.1); }
        .alert { background: #10b981; color: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .error { background: #ef4444; color: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .log-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .log-table th, .log-table td { padding: 12px 15px; text-align: left; border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
        .log-table th { background: rgba(15, 23, 42, 0.5); color: #94a3b8; font-weight: 600; }
        .log-table tr:hover { background: rgba(15, 23, 42, 0.3); }
        .success-log { color: #10b981; }
        .failed-log { color: #ef4444; }
        .time-column { width: 180px; }
        .user-column { width: 150px; }
        .status-column { width: 100px; }
        .ip-column { width: 150px; }
        .filter-buttons { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-button { padding: 8px 16px; background: #475569; color: white; border: none; border-radius: 6px; cursor: pointer; }
        .filter-button:hover { background: #64748b; }
        .filter-button.active { background: #7c3aed; }
        .clear-logs-btn { background: #ef4444 !important; margin-left: auto; }
        .clear-logs-btn:hover { background: #dc2626 !important; }
    </style>
    <script>
        function filterLogs(filter) {
            const rows = document.querySelectorAll('.log-table tbody tr');
            rows.forEach(row => {
                const status = row.querySelector('.status-cell').textContent;
                if (filter === 'all' || 
                    (filter === 'success' && status === 'SUCCESS') || 
                    (filter === 'failed' && status === 'FAILED')) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Update active button
            document.querySelectorAll('.filter-button').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
        }
        
        function clearLogs() {
            if (confirm('Tem certeza que deseja limpar todos os logs de acesso? Esta ação não pode ser desfeita.')) {
                fetch('/clear_logs', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Logs limpos com sucesso!');
                        location.reload();
                    } else {
                        alert('Erro ao limpar logs: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('Erro ao limpar logs: ' + error);
                });
            }
        }
    </script>
</head>
<body>
    <div class="sidebar">
        <h2>Painel</h2>
        <a href="/">Assinaturas</a>
        <a href="/test">Testar Webhook</a>
        <a href="/users">Gerenciar Usuários</a>
        <a href="/backup">Backup & Restore</a>
        <a href="/logs">Logs de Acesso</a>
        <a href="/logout">Sair</a>
    </div>
    <div class="container">
        <h1>📋 Logs de Acesso</h1>
        
        {% if message %}
        <div class="alert">{{ message }}</div>
        {% elif error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h3>Acessos ao Sistema</h3>
                <div class="filter-buttons">
                    <button class="filter-button active" onclick="filterLogs('all')">Todos</button>
                    <button class="filter-button" onclick="filterLogs('success')">Sucesso</button>
                    <button class="filter-button" onclick="filterLogs('failed')">Falhas</button>
                    <button class="filter-button clear-logs-btn" onclick="clearLogs()">🗑️ Limpar Logs</button>
                </div>
            </div>
            
            {% if logs %}
            <table class="log-table">
                <thead>
                    <tr>
                        <th class="time-column">Data/Hora</th>
                        <th class="user-column">Usuário</th>
                        <th class="status-column">Status</th>
                        <th>IP</th>
                        <th>Ação</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr>
                        <td>{{ log.time }}</td>
                        <td><strong>{{ log.user }}</strong></td>
                        <td class="status-cell {% if log.status == 'SUCCESS' %}success-log{% else %}failed-log{% endif %}">
                            {{ log.status }}
                        </td>
                        <td><code>{{ log.ip }}</code></td>
                        <td>{{ log.action }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p style="margin-top: 15px; color: #94a3b8; font-size: 14px;">
                Mostrando {{ logs|length }} registros de acesso. Logs são armazenados em: <code>painel.log</code>
            </p>
            {% else %}
            <p style="text-align: center; padding: 30px; color: #94a3b8;">
                Nenhum registro de acesso encontrado.
            </p>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

# ---------------------------
# Routes
# ---------------------------

NGROK_PUBLIC_URL = None

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_TEMPLATE)
    
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    
    if not username or not password:
        log_action("anonymous", "login_attempt", "empty_fields", False)
        return render_template_string(LOGIN_TEMPLATE, error="Usuário e senha são obrigatórios")
    
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    user = next((u for u in db.get("users", []) if u.get("username") == username), None)
    
    if not user:
        time.sleep(1)
        log_action(username, "login_failed", "user_not_found", False)
        return render_template_string(LOGIN_TEMPLATE, error="Usuário ou senha inválidos")
    
    if user.get("locked", False):
        log_action(username, "login_failed", "account_locked", False)
        return render_template_string(LOGIN_TEMPLATE, error="Conta temporariamente bloqueada")
    
    if not check_password_hash(user.get("password_hash", ""), password):
        if "failed_attempts" not in user:
            user["failed_attempts"] = 0
        user["failed_attempts"] += 1
        
        if user["failed_attempts"] >= 5:
            user["locked"] = True
            user["locked_at"] = datetime.now().isoformat()
            log_action(username, "account_locked", "too_many_failed_attempts", False)
        
        save_json(DB_FILE, db)
        time.sleep(2)
        
        log_action(username, "login_failed", "wrong_password", False)
        return render_template_string(LOGIN_TEMPLATE, error="Usuário ou senha inválidos")
    
    if "failed_attempts" in user:
        user["failed_attempts"] = 0
        user["locked"] = False
        save_json(DB_FILE, db)
    
    session.permanent = True
    session["username"] = username
    session["login_time"] = datetime.now().isoformat()
    session["user_agent"] = request.headers.get("User-Agent", "")
    session["ip_address"] = request.remote_addr
    
    user["last_login"] = datetime.now().isoformat()
    user["last_login_ip"] = request.remote_addr
    save_json(DB_FILE, db)
    
    log_action(username, "login_success", f"ip={request.remote_addr}", True)
    
    if NGROK_PUBLIC_URL and AUTO_REDIRECT_TO_NGROK and request.host.startswith(('localhost', '127.0.0.1')):
        return redirect(f"{NGROK_PUBLIC_URL}/")
    
    return redirect("/")

@app.route("/logout")
def logout():
    if "username" in session:
        log_action(session["username"], "logout", "", True)
    session.clear()
    
    if NGROK_PUBLIC_URL and AUTO_REDIRECT_TO_NGROK:
        return redirect(f"{NGROK_PUBLIC_URL}/login")
    
    return redirect("/login")

@app.route("/")
@login_required
def index():
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    message = request.args.get("message", "")
    
    # Parâmetros de filtro/ordenação da URL
    sort_by = request.args.get("sort", "nome")  # nome, renovacao, compra, dias
    sort_order = request.args.get("order", "asc")  # asc, desc
    filter_type = request.args.get("filter", "all")  # all, mensal, lifetime, expired, active, paused
    
    clientes = db.get("clientes", [])
    
    # Calcular dias para cada cliente (apenas mensais) e preparar para ordenação
    for c in clientes:
        nr = c.get("next_renewal")
        c["dias"] = "-"
        c["dias_num"] = 9999  # Valor alto para lifetime (ficará no final)
        if nr and not c.get("lifetime"):
            try:
                d = datetime.fromisoformat(nr).date()
                diff = (d - date.today()).days
                c["dias"] = diff if diff >= 0 else "Expirado"
                c["dias_num"] = diff
            except Exception:
                pass
        # Preparar datas para ordenação
        c["data_compra_iso"] = c.get("data_compra", "9999-99-99")
        c["next_renewal_iso"] = c.get("next_renewal", "9999-99-99") if not c.get("lifetime") else "9999-99-99"
    
    # Aplicar filtros
    filtered_clientes = []
    for c in clientes:
        # Filtro por tipo
        if filter_type == "mensal" and c.get("lifetime"):
            continue
        elif filter_type == "lifetime" and not c.get("lifetime"):
            continue
        elif filter_type == "expired" and (c.get("lifetime") or c.get("dias_num", 0) >= 0 or c.get("paused")):
            continue
        elif filter_type == "active" and (c.get("paused") or (not c.get("lifetime") and c.get("dias_num", 0) < 0)):
            continue
        elif filter_type == "paused" and not c.get("paused"):
            continue
        
        filtered_clientes.append(c)
    
    # Aplicar ordenação
    reverse_order = (sort_order == "desc")
    
    if sort_by == "nome":
        filtered_clientes.sort(key=lambda x: x.get("nome", "").lower(), reverse=reverse_order)
    elif sort_by == "renovacao":
        filtered_clientes.sort(key=lambda x: (
            not x.get("lifetime"),  # Lifetime primeiro
            x.get("next_renewal_iso", "9999-99-99")
        ), reverse=reverse_order)
    elif sort_by == "compra":
        filtered_clientes.sort(key=lambda x: x.get("data_compra_iso", "9999-99-99"), reverse=reverse_order)
    elif sort_by == "dias":
        filtered_clientes.sort(key=lambda x: (
            not x.get("lifetime"),  # Lifetime primeiro
            x.get("dias_num", 9999)
        ), reverse=reverse_order)
    
    # Calcular estatísticas
    stats = {
        "total": len(clientes),
        "mensal": len([c for c in clientes if not c.get("lifetime")]),
        "lifetime": len([c for c in clientes if c.get("lifetime")]),
        "paused": len([c for c in clientes if c.get("paused")]),
        "expired": len([c for c in clientes if not c.get("lifetime") and c.get("dias_num", 0) < 0])
    }
    
    return render_template_string(MAIN_TEMPLATE, 
                                 clientes=filtered_clientes, 
                                 message=message,
                                 sort=sort_by,
                                 order=sort_order,
                                 filter=filter_type,
                                 stats=stats)

@app.route("/add", methods=["POST"])
@login_required
def add_cliente():
    nome = request.form.get("nome", "").strip()
    discord_id = request.form.get("id", "").strip()
    produto = request.form.get("produto", "").strip()
    preco = request.form.get("preco", "").strip()
    data_compra_str = request.form.get("data_compra", "").strip()
    tipo_plano = request.form.get("tipo_plano", "mensal").strip()
    
    if not nome or not discord_id or not produto or not data_compra_str:
        return redirect(url_for("index", message="Preencha todos os campos obrigatórios"))
    
    if not validate_discord_id(discord_id):
        return redirect(url_for("index", message="ID do Discord deve conter apenas números"))
    
    try:
        data_compra = validate_and_parse_date(data_compra_str)
        
        if tipo_plano == "lifetime":
            next_renewal = None  # Lifetime não tem renovação
            is_lifetime = True
        else:
            next_renewal = data_compra + timedelta(days=30)
            is_lifetime = False
        
    except Exception as e:
        return redirect(url_for("index", message=f"Data inválida: {e}"))
    
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    
    # Verificar se ID já existe
    for cliente in db.get("clientes", []):
        if cliente.get("id") == discord_id:
            return redirect(url_for("index", message="Já existe um cliente com este ID do Discord"))
    
    novo_cliente = {
        "nome": nome,
        "id": discord_id,
        "produto": produto,
        "preco": preco,
        "data_compra": data_compra.isoformat(),
        "next_renewal": next_renewal.isoformat() if next_renewal else None,
        "lifetime": is_lifetime,
        "created_at": datetime.now().isoformat(),
        "last_notified_date": None,
        "paused": False
    }
    
    db["clientes"].append(novo_cliente)
    
    if save_with_backup(DB_FILE, db):
        log_action(session.get("username"), "add_cliente", 
                  f"nome={nome}, id={discord_id}, tipo={'lifetime' if is_lifetime else 'mensal'}", True)
        
        if UPLOAD_ON_CHANGE and BOT_TOKEN and CHANNEL_ID:
            upload_db_to_discord_with_retry(
                DB_FILE,
                content_message="adicionado novo cliente",
                uploaded_by=session.get("username")
            )
        
        return redirect(url_for("index", message="Cliente adicionado com sucesso"))
    else:
        return redirect(url_for("index", message="Erro ao salvar no banco de dados"))

@app.route("/edit/<cid>", methods=["GET", "POST"])
@login_required
def edit_cliente(cid):
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    cliente = next((c for c in db.get("clientes", []) if c.get("id") == cid), None)
    
    if not cliente:
        return redirect(url_for("index", message="Cliente não encontrado"))
    
    if request.method == "GET":
        return render_template_string(EDIT_TEMPLATE, c=cliente)
    
    # POST - Salvar edição
    nome = request.form.get("nome", "").strip()
    discord_id = request.form.get("id", "").strip()
    produto = request.form.get("produto", "").strip()
    preco = request.form.get("preco", "").strip()
    data_compra_str = request.form.get("data_compra", "").strip()
    tipo_plano = request.form.get("tipo_plano", "mensal").strip()
    
    if not nome or not discord_id or not produto or not data_compra_str:
        return redirect(url_for("index", message="Preencha todos os campos obrigatórios"))
    
    if not validate_discord_id(discord_id):
        return redirect(url_for("index", message="ID do Discord deve conter apenas números"))
    
    try:
        data_compra = validate_and_parse_date(data_compra_str)
        
        if tipo_plano == "lifetime":
            next_renewal = None  # Lifetime não tem renovação
            is_lifetime = True
        else:
            next_renewal = data_compra + timedelta(days=30)
            is_lifetime = False
    except Exception as e:
        return redirect(url_for("index", message=f"Data inválida: {e}"))
    
    # Atualizar cliente
    cliente["nome"] = nome
    cliente["id"] = discord_id
    cliente["produto"] = produto
    cliente["preco"] = preco
    cliente["data_compra"] = data_compra.isoformat()
    cliente["next_renewal"] = next_renewal.isoformat() if next_renewal else None
    cliente["lifetime"] = is_lifetime
    cliente["updated_at"] = datetime.now().isoformat()
    
    if save_with_backup(DB_FILE, db):
        log_action(session.get("username"), "edit_cliente", 
                  f"id={cid}->{discord_id}, tipo={'lifetime' if is_lifetime else 'mensal'}", True)
        
        if UPLOAD_ON_CHANGE and BOT_TOKEN and CHANNEL_ID:
            upload_db_to_discord_with_retry(
                DB_FILE,
                content_message=f"cliente editado: {nome}",
                uploaded_by=session.get("username")
            )
        
        return redirect(url_for("index", message="Cliente atualizado com sucesso"))
    else:
        return redirect(url_for("index", message="Erro ao salvar alterações"))

@app.route("/renew/<cid>", methods=["POST"])
@login_required
def renew_cliente(cid):
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    cliente = next((c for c in db.get("clientes", []) if c.get("id") == cid), None)
    
    if not cliente:
        return redirect(url_for("index", message="Cliente não encontrado"))
    
    # Verificar se é lifetime
    if cliente.get("lifetime"):
        return redirect(url_for("index", message="Cliente lifetime não pode ser renovado"))
    
    # Obter data de renovação atual
    current_renewal_str = cliente.get("next_renewal")
    if not current_renewal_str:
        # Se não houver data de renovação, usar data da compra
        current_renewal_str = cliente.get("data_compra")
    
    try:
        current_renewal = datetime.fromisoformat(current_renewal_str).date()
        new_renewal = current_renewal + timedelta(days=30)
        
        # Salvar data anterior para histórico
        previous_renewal = cliente.get("next_renewal")
        cliente["previous_renewal"] = previous_renewal
        cliente["next_renewal"] = new_renewal.isoformat()
        cliente["renewed_at"] = datetime.now().isoformat()
        cliente["renewed_by"] = session.get("username")
        cliente["last_notified_date"] = None  # Resetar notificação para nova data
        
        if save_with_backup(DB_FILE, db):
            log_action(session.get("username"), "renew_cliente", 
                      f"id={cid}, from={previous_renewal}, to={new_renewal.isoformat()}", True)
            
            if UPLOAD_ON_CHANGE and BOT_TOKEN and CHANNEL_ID:
                upload_db_to_discord_with_retry(
                    DB_FILE,
                    content_message=f"cliente renovado: {cliente.get('nome')}",
                    uploaded_by=session.get("username")
                )
            
            # Enviar notificação de renovação com embed
            embed = {
                "title": "🔄 RENOVAÇÃO REALIZADA",
                "color": 2829617,  # Azul
                "fields": [
                    {
                        "name": "💰 Cobrança Automática",
                        "value": (
                            f"**Cliente:** {cliente.get('nome', '—')} "
                            f"(<@{cliente.get('id', '')}>)\n"
                            f"**Produto:** {cliente.get('produto', '—')}"
                        )
                    },
                    {
                        "name": "📆 Informações",
                        "value": (
                            f"• **Última renovação:** {previous_renewal}\n"
                            f"• **Próxima renovação:** {new_renewal.isoformat()}\n"
                            f"• **Renovado por:** {session.get('username')}"
                        )
                    }
                ],
                "footer": {"text": "Sistema de Renovação"},
                "timestamp": datetime.utcnow().isoformat()
            }
            
            send_webhook_with_retry(embeds=[embed])
            
            return redirect(url_for("index", message=f"Cliente renovado! Nova data: {new_renewal.isoformat()}"))
        else:
            return redirect(url_for("index", message="Erro ao salvar renovação"))
            
    except Exception as e:
        logging.error(f"Erro ao renovar cliente {cid}: {e}")
        return redirect(url_for("index", message=f"Erro ao processar renovação: {e}"))

@app.route("/pause/<cid>", methods=["POST"])
@login_required
def pause_cliente(cid):
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    cliente = next((c for c in db.get("clientes", []) if c.get("id") == cid), None)
    
    if not cliente:
        return redirect(url_for("index", message="Cliente não encontrado"))
    
    cliente["paused"] = True
    cliente["paused_at"] = datetime.now().isoformat()
    cliente["paused_by"] = session.get("username")
    
    if save_with_backup(DB_FILE, db):
        log_action(session.get("username"), "pause_cliente", f"id={cid}", True)
        
        if UPLOAD_ON_CHANGE and BOT_TOKEN and CHANNEL_ID:
            upload_db_to_discord_with_retry(
                DB_FILE,
                content_message=f"cliente pausado: {cliente.get('nome')}",
                uploaded_by=session.get("username")
            )
        
        return redirect(url_for("index", message="Cliente pausado com sucesso"))
    else:
        return redirect(url_for("index", message="Erro ao pausar cliente"))

@app.route("/resume/<cid>", methods=["POST"])
@login_required
def resume_cliente(cid):
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    cliente = next((c for c in db.get("clientes", []) if c.get("id") == cid), None)
    
    if not cliente:
        return redirect(url_for("index", message="Cliente não encontrado"))
    
    cliente["paused"] = False
    cliente["resumed_at"] = datetime.now().isoformat()
    cliente["resumed_by"] = session.get("username")
    
    if save_with_backup(DB_FILE, db):
        log_action(session.get("username"), "resume_cliente", f"id={cid}", True)
        
        if UPLOAD_ON_CHANGE and BOT_TOKEN and CHANNEL_ID:
            upload_db_to_discord_with_retry(
                DB_FILE,
                content_message=f"cliente retomado: {cliente.get('nome')}",
                uploaded_by=session.get("username")
            )
        
        return redirect(url_for("index", message="Cliente retomado com sucesso"))
    else:
        return redirect(url_for("index", message="Erro ao retomar cliente"))

@app.route("/delete/<cid>", methods=["POST"])
@login_required
def delete_cliente(cid):
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    
    cliente_removido = None
    for i, cliente in enumerate(db.get("clientes", [])):
        if cliente.get("id") == cid:
            cliente_removido = cliente
            db["clientes"].pop(i)
            break
    
    if not cliente_removido:
        return redirect(url_for("index", message="Cliente não encontrado"))
    
    if save_with_backup(DB_FILE, db):
        log_action(session.get("username"), "delete_cliente", 
                  f"id={cid}, nome={cliente_removido.get('nome')}", True)
        
        if UPLOAD_ON_CHANGE and BOT_TOKEN and CHANNEL_ID:
            upload_db_to_discord_with_retry(
                DB_FILE,
                content_message=f"cliente excluído: {cliente_removido.get('nome')}",
                uploaded_by=session.get("username")
            )
        
        return redirect(url_for("index", message="Cliente excluído com sucesso"))
    else:
        return redirect(url_for("index", message="Erro ao excluir cliente"))

@app.route("/test", methods=["GET"])
@login_required
def test_webhook():
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    return render_template_string(TEST_TEMPLATE, clientes=db.get("clientes", []))

@app.route("/test_send", methods=["POST"])
@login_required
def test_send():
    try:
        idx = int(request.form.get("idx", 0))
    except ValueError:
        return redirect(url_for("test_webhook", error="Índice inválido"))
    
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    clientes = db.get("clientes", [])
    
    if idx < 0 or idx >= len(clientes):
        return redirect(url_for("test_webhook", error="Cliente não encontrado"))
    
    cliente = clientes[idx]
    embed = build_message_profissional(cliente)
    
    # Adicionar marcação de teste
    embed["title"] = f" {embed['title']}"
    embed["color"] = 10197915  # Cinza para teste
    
    ok = send_webhook_with_retry(content="**Teste de Webhook**", embeds=[embed])
    
    if ok:
        log_action(session.get("username"), "test_webhook", 
                  f"cliente={cliente.get('nome')}", True)
        return redirect(url_for("test_webhook", message="Webhook de teste enviado com sucesso"))
    else:
        log_action(session.get("username"), "test_webhook_failed", 
                  f"cliente={cliente.get('nome')}", False)
        return redirect(url_for("test_webhook", error="Falha ao enviar webhook. Verifique a URL."))

@app.route("/users", methods=["GET"])
@admin_required
def users_management():
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    message = request.args.get("message", "")
    error = request.args.get("error", "")
    
    # Não mostrar o hash da senha
    users_safe = []
    for user in db.get("users", []):
        user_copy = user.copy()
        user_copy.pop("password_hash", None)
        users_safe.append(user_copy)
    
    return render_template_string(USERS_TEMPLATE, 
                                 users=users_safe, 
                                 message=message, 
                                 error=error)

@app.route("/add_user", methods=["POST"])
@admin_required
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user").strip()
    
    if not username or not password:
        return redirect(url_for("users_management", error="Usuário e senha são obrigatórios"))
    
    if not validate_username(username):
        return redirect(url_for("users_management", 
                               error="Nome de usuário inválido. Use apenas letras, números, _, -, ."))
    
    valid, msg = validate_password(password)
    if not valid:
        return redirect(url_for("users_management", error=msg))
    
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    
    # Verificar se usuário já existe
    for user in db.get("users", []):
        if user.get("username") == username:
            return redirect(url_for("users_management", error="Usuário já existe"))
    
    new_user = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "role": role,
        "created_at": datetime.now().isoformat(),
        "created_by": session.get("username"),
        "is_super_admin": False,
        "failed_attempts": 0,
        "locked": False
    }
    
    db["users"].append(new_user)
    
    if save_with_backup(DB_FILE, db):
        log_action(session.get("username"), "add_user", f"username={username}, role={role}", True)
        return redirect(url_for("users_management", message="Usuário criado com sucesso"))
    else:
        return redirect(url_for("users_management", error="Erro ao salvar usuário"))

@app.route("/del_user", methods=["POST"])
@admin_required
def del_user():
    username = request.form.get("username", "").strip()
    
    if not username:
        return redirect(url_for("users_management", error="Nome de usuário não especificado"))
    
    if username == session.get("username"):
        return redirect(url_for("users_management", error="Não é possível remover seu próprio usuário"))
    
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    
    # Não permitir remover super admin
    for user in db.get("users", []):
        if user.get("username") == username and user.get("is_super_admin"):
            return redirect(url_for("users_management", 
                                   error="Não é possível remover um super administrador"))
    
    # Remover usuário
    original_count = len(db.get("users", []))
    db["users"] = [u for u in db.get("users", []) if u.get("username") != username]
    
    if len(db.get("users", [])) == original_count:
        return redirect(url_for("users_management", error="Usuário não encontrado"))
    
    if save_with_backup(DB_FILE, db):
        log_action(session.get("username"), "delete_user", f"username={username}", True)
        return redirect(url_for("users_management", message="Usuário removido com sucesso"))
    else:
        return redirect(url_for("users_management", error="Erro ao remover usuário"))

@app.route("/change_password", methods=["POST"])
@admin_required
def change_password():
    username = request.form.get("username", "").strip()
    newpass = request.form.get("newpass", "")
    
    if not username or not newpass:
        return redirect(url_for("users_management", error="Usuário e nova senha são obrigatórios"))
    
    valid, msg = validate_password(newpass)
    if not valid:
        return redirect(url_for("users_management", error=msg))
    
    db = load_json(DB_FILE, {"users": [], "clientes": [], "settings": {}})
    user_found = False
    
    for user in db.get("users", []):
        if user.get("username") == username:
            user["password_hash"] = generate_password_hash(newpass)
            user["password_changed_at"] = datetime.now().isoformat()
            user["password_changed_by"] = session.get("username")
            user["failed_attempts"] = 0
            user["locked"] = False
            user_found = True
            break
    
    if not user_found:
        return redirect(url_for("users_management", error="Usuário não encontrado"))
    
    if save_with_backup(DB_FILE, db):
        log_action(session.get("username"), "change_password", f"for_user={username}", True)
        return redirect(url_for("users_management", message="Senha alterada com sucesso"))
    else:
        return redirect(url_for("users_management", error="Erro ao alterar senha"))

@app.route("/backup", methods=["GET"])
@admin_required
def backup_page():
    message = request.args.get("message", "")
    error = request.args.get("error", "")
    
    # Listar backups disponíveis
    backups = []
    if os.path.exists(BACKUP_DIR):
        for filename in sorted(os.listdir(BACKUP_DIR)):
            if filename.startswith("database_") and filename.endswith(".json"):
                filepath = os.path.join(BACKUP_DIR, filename)
                try:
                    size = os.path.getsize(filepath)
                    size_str = f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                    backups.append({
                        "filename": filename,
                        "size": size_str,
                        "path": filepath
                    })
                except Exception:
                    pass
    
    return render_template_string(
        BACKUP_TEMPLATE,
        backups=backups,
        backup_interval=BACKUP_INTERVAL_HOURS,
        message=message,
        error=error
    )

@app.route("/sync_discord", methods=["POST"])
@admin_required
def sync_discord():
    success = download_db_from_discord_with_retry()
    
    if success:
        log_action(session.get("username"), "sync_from_discord", "", True)
        return redirect(url_for("backup_page", message="Sincronizado do Discord com sucesso"))
    else:
        log_action(session.get("username"), "sync_from_discord_failed", "", False)
        return redirect(url_for("backup_page", error="Falha ao baixar do Discord"))

@app.route("/upload_discord", methods=["POST"])
@admin_required
def upload_discord():
    success = upload_db_to_discord_with_retry(
        DB_FILE,
        content_message=f"upload manual por {session.get('username')}",
        uploaded_by=session.get("username")
    )
    
    if success:
        log_action(session.get("username"), "upload_to_discord", "", True)
        return redirect(url_for("backup_page", message="Upload para Discord realizado com sucesso"))
    else:
        log_action(session.get("username"), "upload_to_discord_failed", "", False)
        return redirect(url_for("backup_page", error="Falha ao fazer upload para Discord"))

@app.route("/create_backup", methods=["POST"])
@admin_required
def create_backup():
    success = backup_database()
    
    if success:
        log_action(session.get("username"), "create_backup", "", True)
        return redirect(url_for("backup_page", message="Backup local criado com sucesso"))
    else:
        log_action(session.get("username"), "create_backup_failed", "", False)
        return redirect(url_for("backup_page", error="Falha ao criar backup"))

@app.route("/restore_backup", methods=["POST"])
@admin_required
def restore_backup():
    filename = request.form.get("filename", "").strip()
    if not filename:
        return redirect(url_for("backup_page", error="Nome do arquivo não especificado"))
    
    backup_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(backup_path):
        return redirect(url_for("backup_page", error="Arquivo de backup não encontrado"))
    
    try:
        # Criar backup do estado atual antes de restaurar
        backup_database()
        
        # Restaurar o backup
        shutil.copy2(backup_path, DB_FILE)
        
        log_action(session.get("username"), "restore_backup", f"file={filename}", True)
        return redirect(url_for("backup_page", message=f"Backup '{filename}' restaurado com sucesso"))
    except Exception as e:
        logging.error(f"Erro ao restaurar backup {filename}: {e}")
        log_action(session.get("username"), "restore_backup_failed", f"file={filename}", False)
        return redirect(url_for("backup_page", error=f"Erro ao restaurar backup: {e}"))

@app.route("/delete_backup", methods=["POST"])
@admin_required
def delete_backup():
    filename = request.form.get("filename", "").strip()
    if not filename:
        return redirect(url_for("backup_page", error="Nome do arquivo não especificado"))
    
    backup_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(backup_path):
        return redirect(url_for("backup_page", error="Arquivo de backup não encontrado"))
    
    try:
        os.remove(backup_path)
        log_action(session.get("username"), "delete_backup", f"file={filename}", True)
        return redirect(url_for("backup_page", message=f"Backup '{filename}' excluído com sucesso"))
    except Exception as e:
        logging.error(f"Erro ao excluir backup {filename}: {e}")
        log_action(session.get("username"), "delete_backup_failed", f"file={filename}", False)
        return redirect(url_for("backup_page", error=f"Erro ao excluir backup: {e}"))

@app.route("/logs", methods=["GET"])
@admin_required
def view_logs():
    """Exibir logs de acesso (apenas admin)"""
    try:
        # Ler arquivo de log ignorando erros de encoding
        if not os.path.exists(LOG_FILE):
            return render_template_string(LOGS_TEMPLATE, 
                                         logs=[], 
                                         error="Arquivo de log não encontrado")
        
        parsed_logs = []
        
        try:
            # Tentar ler com UTF-8 primeiro, ignorando erros
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except:
            # Se falhar, tentar ler como binário e decodificar
            with open(LOG_FILE, "rb") as f:
                content = f.read()
                text = content.decode("utf-8", errors="ignore")
                lines = text.split('\n')
        
        # Filtrar apenas logs de login (sucesso e falha)
        login_logs = []
        for line in lines:
            if "AUDIT - USER:" in line and ("login_success" in line or "login_failed" in line):
                login_logs.append(line.strip())
        
        # Parsear logs para exibição
        for log in login_logs[-100:]:  # Últimos 100 logs
            try:
                # Limpar caracteres especiais
                log = ''.join(char for char in log if ord(char) < 128 or char in 'áéíóúãõâêîôûàèìòùçÁÉÍÓÚÃÕÂÊÎÔÛÀÈÌÒÙÇ')
                
                # Extrair informações do log
                if "[INFO] AUDIT - USER:" in log:
                    parts = log.split("[INFO] AUDIT - USER:")
                    timestamp = parts[0].strip()[:19] if parts[0].strip() else "N/A"
                    log_info = parts[1] if len(parts) > 1 else ""
                    
                    # Extrair usuário
                    user_end = log_info.find(" ACTION:")
                    username = log_info[:user_end] if user_end != -1 else "N/A"
                    
                    # Extrair ação
                    action_start = user_end + 8 if user_end != -1 else 0
                    action_end = log_info.find(" STATUS:", action_start)
                    action = log_info[action_start:action_end] if action_end != -1 else "N/A"
                    
                    # Extrair status
                    status_start = action_end + 8 if action_end != -1 else 0
                    status_end = log_info.find(" DETAILS:", status_start)
                    if status_end == -1:
                        status_end = len(log_info)
                    status = log_info[status_start:status_end] if status_start != -1 else "N/A"
                    
                    # Extrair IP
                    ip = "N/A"
                    if "DETAILS:ip=" in log_info:
                        ip_start = log_info.find("DETAILS:ip=") + 11
                        ip_end = log_info.find(",", ip_start)
                        if ip_end == -1:
                            ip_end = log_info.find(" ", ip_start)
                        if ip_end == -1:
                            ip_end = len(log_info)
                        ip = log_info[ip_start:ip_end]
                    
                    parsed_logs.append({
                        "time": timestamp,
                        "user": username[:50],
                        "action": action[:30],
                        "status": status[:20],
                        "ip": ip[:45]
                    })
                    
            except Exception as e:
                # Se não conseguir parsear, adicionar como raw
                parsed_logs.append({
                    "time": "Erro",
                    "user": "Parse Error",
                    "action": "log_parse_failed",
                    "status": "ERROR",
                    "ip": str(e)[:50]
                })
                continue
        
        # Ordenar do mais recente para o mais antigo
        parsed_logs.reverse()
        
        message = request.args.get("message", "")
        error = request.args.get("error", "")
        
        return render_template_string(LOGS_TEMPLATE, 
                                     logs=parsed_logs, 
                                     message=message, 
                                     error=error)
        
    except Exception as e:
        logging.error(f"Erro ao ler logs: {e}")
        return render_template_string(LOGS_TEMPLATE, 
                                     logs=[], 
                                     error=f"Erro: {str(e)[:100]}")

@app.route("/clear_logs", methods=["POST"])
@admin_required
def clear_logs():
    """Limpar arquivo de logs (apenas admin)"""
    try:
        # Verificar se o arquivo existe
        if not os.path.exists(LOG_FILE):
            return jsonify({"success": False, "error": "Arquivo de log não encontrado"}), 404
        
        # Fazer backup do arquivo atual
        backup_filename = f"painel_log_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        shutil.copy2(LOG_FILE, backup_path)
        
        # Limpar o arquivo de log
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("")
        
        # Log da ação
        log_action(session.get("username"), "clear_logs", 
                  f"backup={backup_filename}", True)
        
        return jsonify({"success": True, "message": "Logs limpos com sucesso"})
        
    except Exception as e:
        logging.error(f"Erro ao limpar logs: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    # Iniciar workers em background
    renewals_thread = threading.Thread(target=renewals_worker, daemon=True)
    backup_thread = threading.Thread(target=backup_periodic_worker, daemon=True)
    
    renewals_thread.start()
    backup_thread.start()
    
    # Tentar baixar DB do Discord na inicialização
    if BOT_TOKEN and CHANNEL_ID:
        logging.info("Tentando baixar DB do Discord na inicialização...")
        download_db_from_discord_with_retry()
    
    # Configurar ngrok se habilitado - MODIFICAÇÃO PARA USAR POWERSHELL
    port = 3000
    ngrok_url = None
    
    if ENABLE_NGROK:
        print(f"\n{'='*60}")
        print(f"🚀 Iniciando Ngrok automaticamente via PowerShell...")
        
        # Verificar se ngrok já está rodando
        if not is_ngrok_running():
            # Iniciar ngrok via PowerShell
            ngrok_url = start_ngrok_via_powershell(port)
            
            if ngrok_url:
                NGROK_PUBLIC_URL = ngrok_url
                print(f"✅ Ngrok iniciado com sucesso!")
                print(f"🌐 Ngrok Public URL: {NGROK_PUBLIC_URL}")
            else:
                print(f"❌ Falha ao iniciar ngrok automaticamente")
                print(f"⚠️  Execute manualmente: Start-Process \"C:\\Users\\lucas\\AppData\\Local\\Programs\\Python\\Python311\\Scripts\\ngrok.exe\" -ArgumentList \"http 3000\" -WindowStyle Hidden")
                NGROK_PUBLIC_URL = None
        else:
            print(f"✅ Ngrok já está em execução")
            # Tentar obter URL do ngrok já em execução
            try:
                response = requests.get("http://localhost:4040/api/tunnels", timeout=5)
                if response.status_code == 200:
                    tunnels = response.json().get("tunnels", [])
                    if tunnels:
                        NGROK_PUBLIC_URL = tunnels[0].get("public_url")
                        print(f"🌐 Ngrok Public URL (já em execução): {NGROK_PUBLIC_URL}")
            except Exception:
                NGROK_PUBLIC_URL = None
        
        print(f"🔗 Local URL: http://localhost:{port}")
        if AUTO_REDIRECT_TO_NGROK and NGROK_PUBLIC_URL:
            print(f"🔄 Auto-redirect: HABILITADO")
        print(f"{'='*60}\n")
    else:
        print(f"\n{'='*60}")
        print(f"🔗 Local URL: http://localhost:{port}")
        print(f"🌐 Ngrok: Desabilitado (configure enable_ngrok: true no config.json)")
        print(f"{'='*60}\n")
        NGROK_PUBLIC_URL = None
    
    # Iniciar Flask
    try:
        app.run(host="0.0.0.0", port=port, debug=False)
    except KeyboardInterrupt:
        logging.info("Servidor interrompido pelo usuário")
        STOP_EVENT.set()
    except Exception as e:
        logging.error(f"Erro ao iniciar servidor: {e}")
        STOP_EVENT.set()