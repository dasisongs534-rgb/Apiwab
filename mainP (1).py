import os
import json
import requests
import hashlib
import secrets
import time
from datetime import datetime, date, timedelta
from flask import Flask, render_template_string, request, session, redirect, jsonify, make_response
from functools import wraps
import re
import logging

# ==========================================
# ⚙️ CONFIGURATION 
# ==========================================
ADMIN_PASSWORD = "admin"
SECRET_KEY = secrets.token_hex(32)
VERSION = "2.0.0"
MAX_KEYS_PER_USER = 100
API_NAME = "Aditya API Hub"

# ==========================================
# 📁 DATABASE SETUP 
# ==========================================
KEYS_FILE = "api_keys.json"
SETTINGS_FILE = "api_settings.json"
ANALYTICS_FILE = "analytics.json"
BLACKLIST_FILE = "blacklist.json"
RATE_LIMIT_FILE = "rate_limits.json"
CUSTOM_APIS_FILE = "custom_apis.json"

DEFAULT_SETTINGS = {
    "number_api": "https://exploitsindia.site/osint/api.php?key=anish-exploits&type=number&num=",
    "vehicle_api": "https://osint.invalidayushh.workers.dev/vnum?key=bittu1410-14d-demo&q=",
    "email_api": "https://api.example.com/email?q=",
    "whatsapp_api": "https://api.example.com/whatsapp?q=",
    "maintenance_mode": False,
    "allow_public_access": True,
    "rate_limit_per_minute": 60,
    "enable_logging": True,
    "cache_enabled": True,
    "cache_duration": 300,
    "blacklist_enabled": True,
    "auto_block_threshold": 50,
    "enable_credit": True,
    "credit_text": "@Aditya_dark0"
}

def load_data(filepath, default_data):
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            return default_data
    return default_data

def save_data(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def get_keys():
    data = load_data(KEYS_FILE, {})
    today_str = str(date.today())
    updated = False
    
    for k, v in data.items():
        if v.get('last_used_date') != today_str:
            v['used'] = 0
            v['last_used_date'] = today_str
            updated = True
            
    if updated:
        save_data(KEYS_FILE, data)
    return data

def get_analytics():
    return load_data(ANALYTICS_FILE, {
        "total_requests": 0,
        "daily_requests": {},
        "api_usage": {},
        "error_logs": [],
        "user_agents": {},
        "top_ips": {}
    })

def update_analytics(api_key, api_type, status, ip, user_agent):
    analytics = get_analytics()
    
    analytics["total_requests"] += 1
    
    today = str(date.today())
    if today not in analytics["daily_requests"]:
        analytics["daily_requests"][today] = 0
    analytics["daily_requests"][today] += 1
    
    if api_type not in analytics["api_usage"]:
        analytics["api_usage"][api_type] = 0
    analytics["api_usage"][api_type] += 1
    
    if user_agent:
        if user_agent not in analytics["user_agents"]:
            analytics["user_agents"][user_agent] = 0
        analytics["user_agents"][user_agent] += 1
    
    if ip:
        if ip not in analytics["top_ips"]:
            analytics["top_ips"][ip] = 0
        analytics["top_ips"][ip] += 1
        
    if len(analytics["top_ips"]) > 1000:
        analytics["top_ips"] = dict(sorted(analytics["top_ips"].items(), key=lambda x: x[1], reverse=True)[:1000])
    
    save_data(ANALYTICS_FILE, analytics)

def log_error(error_type, message, api_key=None, query=None):
    analytics = get_analytics()
    analytics["error_logs"].append({
        "timestamp": datetime.now().isoformat(),
        "type": error_type,
        "message": message,
        "api_key": api_key,
        "query": query
    })
    if len(analytics["error_logs"]) > 500:
        analytics["error_logs"] = analytics["error_logs"][-500:]
    save_data(ANALYTICS_FILE, analytics)

def get_blacklist():
    return load_data(BLACKLIST_FILE, {"ips": [], "keys": []})

def update_blacklist(entry_type, entry, action="add"):
    blacklist = get_blacklist()
    if action == "add":
        if entry not in blacklist[entry_type]:
            blacklist[entry_type].append(entry)
    elif action == "remove":
        if entry in blacklist[entry_type]:
            blacklist[entry_type].remove(entry)
    save_data(BLACKLIST_FILE, blacklist)

def get_custom_apis():
    return load_data(CUSTOM_APIS_FILE, {})

def save_custom_api(api_name, api_url):
    custom_apis = get_custom_apis()
    custom_apis[api_name] = api_url
    save_data(CUSTOM_APIS_FILE, custom_apis)

def delete_custom_api(api_name):
    custom_apis = get_custom_apis()
    if api_name in custom_apis:
        del custom_apis[api_name]
        save_data(CUSTOM_APIS_FILE, custom_apis)
        return True
    return False

# ==========================================
# 🌐 FLASK WEB SERVER
# ==========================================
app = Flask(__name__)
app.secret_key = SECRET_KEY

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_check(ip):
    rate_limits = load_data(RATE_LIMIT_FILE, {})
    current_minute = int(time.time() / 60)
    
    if ip not in rate_limits:
        rate_limits[ip] = {"minute": current_minute, "count": 0}
    
    if rate_limits[ip]["minute"] != current_minute:
        rate_limits[ip] = {"minute": current_minute, "count": 0}
    
    rate_limits[ip]["count"] += 1
    save_data(RATE_LIMIT_FILE, rate_limits)
    
    settings = load_data(SETTINGS_FILE, DEFAULT_SETTINGS)
    return rate_limits[ip]["count"] <= settings.get("rate_limit_per_minute", 60)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>🔥 Aditya API Hub v2.0</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0a; 
            min-height: 100vh;
            color: #e0e0e0;
            background-image: radial-gradient(circle at 20% 50%, rgba(52, 152, 219, 0.05) 0%, transparent 50%),
                              radial-gradient(circle at 80% 50%, rgba(231, 76, 60, 0.05) 0%, transparent 50%);
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 15px;
        }
        
        .glass {
            background: rgba(20, 20, 30, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            padding: 20px;
            transition: all 0.3s ease;
        }
        
        .glass:hover {
            border-color: rgba(52, 152, 219, 0.2);
            box-shadow: 0 8px 40px rgba(52, 152, 219, 0.1);
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            margin-bottom: 20px;
            background: rgba(20, 20, 30, 0.95);
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .logo i {
            font-size: 30px;
            color: #e74c3c;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        
        .logo h1 {
            font-size: 22px;
            background: linear-gradient(135deg, #e74c3c, #f39c12);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 800;
        }
        
        .logo span {
            font-size: 12px;
            color: #7f8c8d;
            -webkit-text-fill-color: #7f8c8d;
        }
        
        .header-actions {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-online {
            background: rgba(46, 204, 113, 0.2);
            color: #2ecc71;
            border: 1px solid rgba(46, 204, 113, 0.3);
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            text-decoration: none;
            white-space: nowrap;
        }
        
        .btn-primary { background: #3498db; color: white; }
        .btn-primary:hover { background: #2980b9; transform: translateY(-2px); box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3); }
        
        .btn-success { background: #2ecc71; color: white; }
        .btn-success:hover { background: #27ae60; transform: translateY(-2px); box-shadow: 0 4px 15px rgba(46, 204, 113, 0.3); }
        
        .btn-danger { background: #e74c3c; color: white; }
        .btn-danger:hover { background: #c0392b; transform: translateY(-2px); box-shadow: 0 4px 15px rgba(231, 76, 60, 0.3); }
        
        .btn-warning { background: #f39c12; color: white; }
        .btn-warning:hover { background: #e67e22; transform: translateY(-2px); }
        
        .btn-info { background: #9b59b6; color: white; }
        .btn-info:hover { background: #8e44ad; transform: translateY(-2px); }
        
        .btn-outline {
            background: transparent;
            border: 2px solid #3498db;
            color: #3498db;
        }
        .btn-outline:hover { background: #3498db; color: white; }
        
        .btn-sm { padding: 4px 10px; font-size: 11px; }
        .btn-lg { padding: 12px 24px; font-size: 15px; }
        .btn-block { width: 100%; justify-content: center; }
        
        .login-container {
            max-width: 400px;
            margin: 60px auto;
            padding: 0 15px;
        }
        
        .login-container .glass {
            padding: 40px 30px;
            text-align: center;
        }
        
        .login-container .logo-icon {
            font-size: 48px;
            color: #e74c3c;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #bdc3c7;
        }
        
        .form-control {
            width: 100%;
            padding: 10px 14px;
            background: rgba(255, 255, 255, 0.05);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: white;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 20px rgba(52, 152, 219, 0.1);
        }
        
        .form-control::placeholder {
            color: #7f8c8d;
        }
        
        select.form-control {
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='white' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 12px center;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: rgba(20, 20, 30, 0.95);
            padding: 15px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            transition: all 0.3s ease;
            text-align: center;
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            border-color: rgba(52, 152, 219, 0.2);
        }
        
        .stat-card .stat-icon {
            font-size: 20px;
            margin-bottom: 8px;
        }
        
        .stat-card .stat-number {
            font-size: 24px;
            font-weight: 700;
            background: linear-gradient(135deg, #e74c3c, #f39c12);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .stat-card .stat-label {
            font-size: 11px;
            color: #7f8c8d;
            margin-top: 4px;
        }
        
        .table-container {
            overflow-x: auto;
            margin-top: 15px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 600px;
        }
        
        th {
            background: rgba(52, 152, 219, 0.1);
            padding: 10px 12px;
            text-align: left;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #bdc3c7;
            border-bottom: 2px solid rgba(255, 255, 255, 0.05);
        }
        
        td {
            padding: 10px 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 12px;
        }
        
        tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
        }
        
        .badge-number { background: rgba(52, 152, 219, 0.2); color: #3498db; }
        .badge-vehicle { background: rgba(46, 204, 113, 0.2); color: #2ecc71; }
        .badge-email { background: rgba(155, 89, 182, 0.2); color: #9b59b6; }
        .badge-whatsapp { background: rgba(46, 204, 113, 0.2); color: #27ae60; }
        .badge-custom { background: rgba(243, 156, 18, 0.2); color: #f39c12; }
        .badge-expired { background: rgba(231, 76, 60, 0.2); color: #e74c3c; }
        .badge-active { background: rgba(46, 204, 113, 0.2); color: #2ecc71; }
        
        .copy-btn {
            background: rgba(243, 156, 18, 0.2);
            color: #f39c12;
            border: 1px solid rgba(243, 156, 18, 0.3);
            padding: 4px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            transition: all 0.3s ease;
            margin-top: 4px;
        }
        
        .copy-btn:hover {
            background: #f39c12;
            color: white;
        }
        
        .copy-btn.copied {
            background: #2ecc71;
            color: white;
            border-color: #2ecc71;
        }
        
        .url-display {
            background: rgba(0, 0, 0, 0.3);
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 10px;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            border-left: 3px solid #3498db;
            max-width: 250px;
            margin-bottom: 4px;
        }
        
        .settings-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 15px;
        }
        
        /* MOBILE RESPONSIVE - Key Generation Section */
        .key-gen-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }
        
        .key-gen-grid .form-group {
            margin-bottom: 0;
        }
        
        .key-gen-grid .full-width {
            grid-column: 1 / -1;
        }
        
        .custom-api-grid {
            display: grid;
            grid-template-columns: 1fr 1fr auto;
            gap: 10px;
            align-items: end;
        }
        
        .custom-api-grid .form-group {
            margin-bottom: 0;
        }
        
        @media (max-width: 768px) {
            .key-gen-grid {
                grid-template-columns: 1fr;
            }
            .key-gen-grid .full-width {
                grid-column: 1;
            }
            .settings-grid {
                grid-template-columns: 1fr;
            }
            .custom-api-grid {
                grid-template-columns: 1fr;
            }
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .header {
                flex-direction: column;
                align-items: stretch;
                text-align: center;
            }
            .header-actions {
                justify-content: center;
            }
            .logo {
                justify-content: center;
            }
            .glass {
                padding: 15px;
            }
            .container {
                padding: 10px;
            }
            .url-display {
                max-width: 150px;
                font-size: 9px;
            }
        }
        
        @media (max-width: 480px) {
            .stats-grid {
                grid-template-columns: 1fr 1fr;
                gap: 10px;
            }
            .stat-card .stat-number {
                font-size: 20px;
            }
            .logo h1 {
                font-size: 18px;
            }
            .btn {
                font-size: 12px;
                padding: 6px 12px;
            }
            .header-actions {
                gap: 6px;
            }
        }
        
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(46, 204, 113, 0.95);
            color: white;
            padding: 14px 20px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            display: none;
            animation: slideUp 0.3s ease;
            z-index: 1000;
            font-size: 14px;
        }
        
        @keyframes slideUp {
            from { transform: translateY(100px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .toggle {
            position: relative;
            display: inline-block;
            width: 44px;
            height: 24px;
        }
        
        .toggle input { opacity: 0; width: 0; height: 0; }
        
        .toggle .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: #2c3e50;
            transition: .3s;
            border-radius: 24px;
        }
        
        .toggle .slider:before {
            position: absolute;
            content: "";
            height: 16px;
            width: 16px;
            left: 4px;
            bottom: 4px;
            background: white;
            transition: .3s;
            border-radius: 50%;
        }
        
        .toggle input:checked + .slider { background: #3498db; }
        .toggle input:checked + .slider:before { transform: translateX(20px); }
        
        .flex-between {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .text-muted { color: #7f8c8d; font-size: 12px; }
        .mt-20 { margin-top: 20px; }
        .mb-20 { margin-bottom: 20px; }
        .gap-10 { gap: 10px; }
        .flex { display: flex; align-items: center; flex-wrap: wrap; }
        
        .credit-section {
            background: rgba(231, 76, 60, 0.05);
            border: 1px solid rgba(231, 76, 60, 0.2);
            border-radius: 8px;
            padding: 12px;
            margin-top: 10px;
            text-align: center;
        }
        
        .credit-section .credit-text {
            color: #f39c12;
            font-weight: 600;
        }
        
        .section-title {
            color: #e74c3c;
            margin-bottom: 15px;
            font-size: 18px;
        }
        
        .section-title i {
            margin-right: 8px;
        }
        
        .custom-api-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: rgba(255,255,255,0.03);
            border-radius: 6px;
            margin-bottom: 6px;
            border-left: 3px solid #f39c12;
            flex-wrap: wrap;
            gap: 8px;
        }
        
        .custom-api-item .api-name {
            color: #3498db;
            font-weight: 600;
            font-size: 13px;
        }
        
        .custom-api-item .api-url {
            color: #7f8c8d;
            font-size: 11px;
            word-break: break-all;
            max-width: 60%;
        }
        
        .custom-api-item .api-actions {
            display: flex;
            gap: 6px;
        }
        
        .delete-api-btn {
            background: rgba(231, 76, 60, 0.2);
            color: #e74c3c;
            border: 1px solid rgba(231, 76, 60, 0.3);
            padding: 2px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            transition: all 0.3s ease;
        }
        
        .delete-api-btn:hover {
            background: #e74c3c;
            color: white;
        }
        
        .url-cell {
            min-width: 200px;
        }
    </style>
</head>
<body>

<div class="container">
    {% if not logged_in %}
        <!-- Login Page -->
        <div class="login-container">
            <div class="glass">
                <div class="logo-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <h2 style="margin-bottom: 10px; background: linear-gradient(135deg, #e74c3c, #f39c12); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Aditya API Hub</h2>
                <p style="color: #7f8c8d; margin-bottom: 25px; -webkit-text-fill-color: #7f8c8d; font-size: 14px;">Secure API Management System</p>
                <form method="POST" action="/login">
                    <div class="form-group">
                        <input type="password" name="password" class="form-control" placeholder="Enter Admin Password" required>
                    </div>
                    <button type="submit" class="btn btn-danger btn-lg btn-block">
                        <i class="fas fa-lock"></i> Access Dashboard
                    </button>
                </form>
                <div style="margin-top: 15px; font-size: 12px; color: #7f8c8d;">
                    <i class="fas fa-code"></i> Developed by @Aditya_dark0
                </div>
            </div>
        </div>
    {% else %}
        <!-- Dashboard -->
        <div class="header glass">
            <div class="logo">
                <i class="fas fa-robot"></i>
                <div>
                    <h1>Aditya API Hub</h1>
                    <span>v{{ version }} • Premium API Management</span>
                </div>
            </div>
            <div class="header-actions">
                <span class="status-badge status-online">
                    <i class="fas fa-circle" style="font-size: 8px;"></i> Online
                </span>
                <button class="btn btn-outline btn-sm" onclick="refreshPage()">
                    <i class="fas fa-sync-alt"></i> Refresh
                </button>
                <a href="/logout" class="btn btn-danger btn-sm">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </a>
            </div>
        </div>
        
        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-keys" style="color: #3498db;"></i></div>
                <div class="stat-number">{{ keys|length }}</div>
                <div class="stat-label">Total API Keys</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-chart-line" style="color: #2ecc71;"></i></div>
                <div class="stat-number">{{ analytics.total_requests|default(0) }}</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-calendar-day" style="color: #f39c12;"></i></div>
                <div class="stat-number">{{ analytics.daily_requests.get(today, 0)|default(0) }}</div>
                <div class="stat-label">Today's Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-server" style="color: #9b59b6;"></i></div>
                <div class="stat-number">{{ analytics.api_usage|length }}</div>
                <div class="stat-label">Active APIs</div>
            </div>
        </div>
        
        <!-- Create Key Form - FULLY EXPANDED -->
        <div class="glass mb-20">
            <h3 class="section-title">
                <i class="fas fa-plus-circle"></i> Generate New API Key
            </h3>
            <form method="POST" action="/generate">
                <div class="key-gen-grid">
                    <div class="form-group">
                        <label>Key Name</label>
                        <input type="text" name="key_name" class="form-control" placeholder="e.g., premium_user" required>
                    </div>
                    <div class="form-group">
                        <label>Daily Limit</label>
                        <input type="number" name="limit" class="form-control" placeholder="0 = Unlimited" required>
                    </div>
                    <div class="form-group">
                        <label>Expiry Date</label>
                        <input type="date" name="expiry" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>API Type</label>
                        <select name="type" class="form-control">
                            <option value="number">📱 Number API</option>
                            <option value="vehicle">🚗 Vehicle API</option>
                            <option value="email">📧 Email API</option>
                            <option value="whatsapp">💬 WhatsApp API</option>
                            {% for api_name in custom_apis.keys() %}
                                <option value="{{ api_name }}">🔧 {{ api_name|upper }} API</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group full-width">
                        <button type="submit" class="btn btn-success btn-block" style="height: 48px;">
                            <i class="fas fa-key"></i> Create API Key
                        </button>
                    </div>
                </div>
            </form>
            <div class="credit-section">
                <i class="fas fa-code" style="color: #e74c3c;"></i>
                <span class="credit-text">Powered by @Aditya_dark0</span>
            </div>
        </div>
        
        <!-- Custom API Management -->
        <div class="glass mb-20">
            <h3 class="section-title" style="color: #f39c12;">
                <i class="fas fa-plug"></i> Add Custom API
            </h3>
            <form method="POST" action="/add_custom_api">
                <div class="custom-api-grid">
                    <div class="form-group">
                        <label>API Name</label>
                        <input type="text" name="api_name" class="form-control" placeholder="e.g., telegram" required>
                    </div>
                    <div class="form-group">
                        <label>API URL</label>
                        <input type="url" name="api_url" class="form-control" placeholder="https://api.example.com?q=" required>
                    </div>
                    <button type="submit" class="btn btn-info" style="height: 44px;">
                        <i class="fas fa-plus"></i> Add API
                    </button>
                </div>
            </form>
            
            {% if custom_apis %}
                <div style="margin-top: 15px;">
                    <h4 style="color: #bdc3c7; font-size: 13px; margin-bottom: 10px;">
                        <i class="fas fa-list"></i> Your Custom APIs
                    </h4>
                    {% for api_name, api_url in custom_apis.items() %}
                        <div class="custom-api-item">
                            <span class="api-name">{{ api_name|upper }}</span>
                            <span class="api-url">{{ api_url }}</span>
                            <div class="api-actions">
                                <form method="POST" action="/delete_custom_api" style="display: inline;">
                                    <input type="hidden" name="api_name" value="{{ api_name }}">
                                    <button type="submit" class="delete-api-btn" onclick="return confirm('Delete this custom API?')">
                                        <i class="fas fa-trash"></i> Delete
                                    </button>
                                </form>
                            </div>
                        </div>
                    {% endfor %}
                </div>
            {% endif %}
        </div>
        
        <!-- Keys Table -->
        <div class="glass">
            <div class="flex-between mb-20">
                <h3 style="color: #2ecc71; font-size: 18px;">
                    <i class="fas fa-database"></i> Active API Keys
                </h3>
                <span class="text-muted">{{ keys|length }} keys total</span>
            </div>
            
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Key Name</th>
                            <th>Type</th>
                            <th>Usage</th>
                            <th>Expiry</th>
                            <th>Status</th>
                            <th>Live Endpoint</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for k, v in keys.items() %}
                        <tr>
                            <td>
                                <strong style="color: #3498db; font-size: 12px;">{{ k }}</strong>
                            </td>
                            <td>
                                <span class="badge badge-{{ v.api_type }}">
                                    {{ v.api_type|upper }}
                                </span>
                            </td>
                            <td>{{ v.used }} / {% if v.limit == 0 %}∞{% else %}{{ v.limit }}{% endif %}</td>
                            <td style="font-size: 11px;">{{ v.expiry_date }}</td>
                            <td>
                                {% if v.expiry_date < today %}
                                    <span class="badge badge-expired"><i class="fas fa-times-circle"></i> Expired</span>
                                {% else %}
                                    <span class="badge badge-active"><i class="fas fa-check-circle"></i> Active</span>
                                {% endif %}
                            </td>
                            <td class="url-cell">
                                <div class="url-display" id="url_{{ loop.index }}">
                                    {{ host_url }}api/v1/info?key={{ k }}&query=9876543210
                                </div>
                                <button class="copy-btn" onclick="copyToClipboard('url_{{ loop.index }}', this)">
                                    <i class="fas fa-copy"></i> Copy URL
                                </button>
                            </td>
                            <td>
                                <form method="POST" action="/delete_key" style="display: inline;">
                                    <input type="hidden" name="key_name" value="{{ k }}">
                                    <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete this key?')">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </form>
                                <form method="POST" action="/reset_key" style="display: inline;">
                                    <input type="hidden" name="key_name" value="{{ k }}">
                                    <button type="submit" class="btn btn-warning btn-sm" onclick="return confirm('Reset usage for this key?')">
                                        <i class="fas fa-undo"></i>
                                    </button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Advanced Settings -->
        <div class="glass mt-20">
            <h3 class="section-title" style="color: #f39c12;">
                <i class="fas fa-cog"></i> Advanced Settings
            </h3>
            
            <div class="settings-grid">
                <!-- API Endpoints -->
                <div>
                    <h4 style="color: #bdc3c7; margin-bottom: 12px; font-size: 13px;">
                        <i class="fas fa-link"></i> Backend API Endpoints
                    </h4>
                    <form method="POST" action="/update_settings">
                        <div class="form-group">
                            <label>Number API URL</label>
                            <input type="text" name="num" class="form-control" value="{{ settings.number_api }}" required>
                        </div>
                        <div class="form-group">
                            <label>Vehicle API URL</label>
                            <input type="text" name="veh" class="form-control" value="{{ settings.vehicle_api }}" required>
                        </div>
                        <div class="form-group">
                            <label>Email API URL</label>
                            <input type="text" name="email" class="form-control" value="{{ settings.email_api }}" placeholder="https://api.example.com/email?q=">
                        </div>
                        <div class="form-group">
                            <label>WhatsApp API URL</label>
                            <input type="text" name="whatsapp" class="form-control" value="{{ settings.whatsapp_api }}" placeholder="https://api.example.com/whatsapp?q=">
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">
                            <i class="fas fa-save"></i> Save Endpoints
                        </button>
                    </form>
                </div>
                
                <!-- System Settings -->
                <div>
                    <h4 style="color: #bdc3c7; margin-bottom: 12px; font-size: 13px;">
                        <i class="fas fa-sliders-h"></i> System Configuration
                    </h4>
                    <form method="POST" action="/update_config">
                        <div class="form-group">
                            <div class="flex flex-between">
                                <label>Maintenance Mode</label>
                                <label class="toggle">
                                    <input type="checkbox" name="maintenance_mode" {% if settings.maintenance_mode %}checked{% endif %}>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="flex flex-between">
                                <label>Enable Logging</label>
                                <label class="toggle">
                                    <input type="checkbox" name="enable_logging" {% if settings.enable_logging %}checked{% endif %}>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="flex flex-between">
                                <label>Enable Cache</label>
                                <label class="toggle">
                                    <input type="checkbox" name="cache_enabled" {% if settings.cache_enabled %}checked{% endif %}>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="flex flex-between">
                                <label>Enable Credits</label>
                                <label class="toggle">
                                    <input type="checkbox" name="enable_credit" {% if settings.enable_credit %}checked{% endif %}>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Rate Limit (requests/minute)</label>
                            <input type="number" name="rate_limit_per_minute" class="form-control" value="{{ settings.rate_limit_per_minute }}">
                        </div>
                        <button type="submit" class="btn btn-warning btn-block">
                            <i class="fas fa-save"></i> Update Configuration
                        </button>
                    </form>
                </div>
                
                <!-- Analytics -->
                <div>
                    <h4 style="color: #bdc3c7; margin-bottom: 12px; font-size: 13px;">
                        <i class="fas fa-chart-bar"></i> Analytics
                    </h4>
                    <div style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; max-height: 250px; overflow-y: auto;">
                        <div style="margin-bottom: 8px;">
                            <strong style="color: #3498db; font-size: 12px;">API Usage:</strong>
                            {% for api, count in analytics.api_usage.items() %}
                                <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 12px;">
                                    <span>{{ api|upper }}</span>
                                    <span style="color: #3498db;">{{ count }}</span>
                                </div>
                            {% endfor %}
                        </div>
                        <div>
                            <strong style="color: #e74c3c; font-size: 12px;">Recent Errors:</strong>
                            {% for error in analytics.error_logs[-3:]|reverse %}
                                <div style="padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 11px;">
                                    <span style="color: #e74c3c;">[{{ error.type }}]</span>
                                    <span style="color: #7f8c8d;">{{ error.message[:35] }}...</span>
                                </div>
                            {% endfor %}
                        </div>
                    </div>
                    <div style="margin-top: 12px; text-align: center; font-size: 11px; color: #7f8c8d;">
                        <i class="fas fa-code"></i> Powered by @Aditya_dark0
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div style="text-align: center; margin-top: 25px; padding: 15px; color: #7f8c8d; font-size: 12px; border-top: 1px solid rgba(255,255,255,0.05);">
            <i class="fas fa-shield-alt"></i> Aditya API Hub v{{ version }} • 
            <span style="color: #f39c12;">Developed by @Aditya_dark0</span> • 
            <i class="fas fa-lock"></i> Secure & Encrypted
        </div>
    {% endif %}
</div>

<!-- Toast Notification -->
<div id="toast" class="toast">
    <i class="fas fa-check-circle"></i> <span id="toastMessage">Copied!</span>
</div>

<script>
    function copyToClipboard(elementId, buttonElement) {
        // Get the text from the element
        const element = document.getElementById(elementId);
        let text = element.innerText;
        
        // Check if we're in a secure context (HTTPS or localhost)
        const isSecureContext = window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
        
        if (isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
            // Use Clipboard API
            navigator.clipboard.writeText(text).then(function() {
                showToast('URL copied to clipboard! ✅');
                if (buttonElement) {
                    buttonElement.classList.add('copied');
                    buttonElement.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    setTimeout(() => {
                        buttonElement.classList.remove('copied');
                        buttonElement.innerHTML = '<i class="fas fa-copy"></i> Copy URL';
                    }, 2000);
                }
            }).catch(function(err) {
                // Fallback for clipboard errors
                fallbackCopy(text, buttonElement);
            });
        } else {
            // Fallback for non-secure contexts
            fallbackCopy(text, buttonElement);
        }
    }
    
    function fallbackCopy(text, buttonElement) {
        // Create a temporary textarea
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        textarea.style.left = '-9999px';
        textarea.style.top = '-9999px';
        document.body.appendChild(textarea);
        
        // Select and copy
        textarea.select();
        textarea.setSelectionRange(0, textarea.value.length);
        
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                showToast('URL copied to clipboard! ✅');
                if (buttonElement) {
                    buttonElement.classList.add('copied');
                    buttonElement.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    setTimeout(() => {
                        buttonElement.classList.remove('copied');
                        buttonElement.innerHTML = '<i class="fas fa-copy"></i> Copy URL';
                    }, 2000);
                }
            } else {
                showToast('Failed to copy. Please select and copy manually.');
            }
        } catch (err) {
            showToast('Failed to copy. Please select and copy manually.');
        }
        
        // Clean up
        document.body.removeChild(textarea);
    }
    
    function showToast(message) {
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');
        toastMessage.textContent = message;
        toast.style.display = 'block';
        toast.style.animation = 'none';
        setTimeout(() => {
            toast.style.animation = 'slideUp 0.3s ease';
        }, 10);
        clearTimeout(toast._timeout);
        toast._timeout = setTimeout(() => {
            toast.style.display = 'none';
        }, 3000);
    }
    
    function refreshPage() {
        location.reload();
    }
    
    // Close toast on click
    document.getElementById('toast').addEventListener('click', function() {
        this.style.display = 'none';
        clearTimeout(this._timeout);
    });
</script>
</body>
</html>
"""

# ==========================================
# 🌐 ROUTES
# ==========================================

@app.route('/')
def dashboard():
    analytics = get_analytics()
    settings = load_data(SETTINGS_FILE, DEFAULT_SETTINGS)
    custom_apis = get_custom_apis()
    
    # Ensure all required keys exist in settings
    for key, value in DEFAULT_SETTINGS.items():
        if key not in settings:
            settings[key] = value
    
    return render_template_string(
        HTML_TEMPLATE,
        logged_in=session.get('admin'),
        keys=get_keys(),
        settings=settings,
        host_url=request.url_root,
        analytics=analytics,
        today=str(date.today()),
        version=VERSION,
        custom_apis=custom_apis
    )

@app.route('/login', methods=['POST'])
def login():
    if request.form.get('password') == ADMIN_PASSWORD:
        session['admin'] = True
        session['login_time'] = datetime.now().isoformat()
    return redirect('/')

@app.route('/generate', methods=['POST'])
@admin_required
def generate_web():
    keys = get_keys()
    key_name = request.form.get('key_name')
    
    if len(keys) >= MAX_KEYS_PER_USER:
        return "Maximum keys limit reached!", 400
    
    keys[key_name] = {
        "limit": int(request.form.get('limit')),
        "used": 0,
        "expiry_date": request.form.get('expiry'),
        "api_type": request.form.get('type'),
        "last_used_date": str(date.today()),
        "created_at": datetime.now().isoformat(),
        "created_by": request.remote_addr
    }
    save_data(KEYS_FILE, keys)
    return redirect('/')

@app.route('/delete_key', methods=['POST'])
@admin_required
def delete_web():
    keys = get_keys()
    keys.pop(request.form.get('key_name'), None)
    save_data(KEYS_FILE, keys)
    return redirect('/')

@app.route('/reset_key', methods=['POST'])
@admin_required
def reset_key():
    keys = get_keys()
    key_name = request.form.get('key_name')
    if key_name in keys:
        keys[key_name]['used'] = 0
        keys[key_name]['last_used_date'] = str(date.today())
        save_data(KEYS_FILE, keys)
    return redirect('/')

@app.route('/update_settings', methods=['POST'])
@admin_required
def update_web():
    settings = load_data(SETTINGS_FILE, DEFAULT_SETTINGS)
    settings.update({
        "number_api": request.form.get('num'),
        "vehicle_api": request.form.get('veh'),
        "email_api": request.form.get('email', settings.get('email_api', '')),
        "whatsapp_api": request.form.get('whatsapp', settings.get('whatsapp_api', ''))
    })
    save_data(SETTINGS_FILE, settings)
    return redirect('/')

@app.route('/update_config', methods=['POST'])
@admin_required
def update_config():
    settings = load_data(SETTINGS_FILE, DEFAULT_SETTINGS)
    settings.update({
        "maintenance_mode": 'maintenance_mode' in request.form,
        "enable_logging": 'enable_logging' in request.form,
        "cache_enabled": 'cache_enabled' in request.form,
        "enable_credit": 'enable_credit' in request.form,
        "rate_limit_per_minute": int(request.form.get('rate_limit_per_minute', 60))
    })
    save_data(SETTINGS_FILE, settings)
    return redirect('/')

@app.route('/add_custom_api', methods=['POST'])
@admin_required
def add_custom_api():
    api_name = request.form.get('api_name', '').strip().lower()
    api_url = request.form.get('api_url', '').strip()
    
    if api_name and api_url:
        # Sanitize API name
        api_name = re.sub(r'[^a-zA-Z0-9_]', '', api_name)
        save_custom_api(api_name, api_url)
    
    return redirect('/')

@app.route('/delete_custom_api', methods=['POST'])
@admin_required
def delete_custom_api_route():
    api_name = request.form.get('api_name')
    if api_name:
        delete_custom_api(api_name)
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('admin', None)
    session.pop('login_time', None)
    return redirect('/')

# ==========================================
# 🌐 MAIN API ENDPOINT (Enhanced)
# ==========================================

cache_store = {}

@app.route('/api/v1/info', methods=['GET', 'POST'])
def api_endpoint():
    settings = load_data(SETTINGS_FILE, DEFAULT_SETTINGS)
    
    if settings.get('maintenance_mode', False):
        return jsonify({"error": "API is under maintenance. Please try again later."}), 503
    
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    if settings.get('blacklist_enabled', True):
        blacklist = get_blacklist()
        if client_ip in blacklist.get('ips', []):
            return jsonify({"error": "Your IP has been blocked due to suspicious activity."}), 403
    
    if not rate_limit_check(client_ip):
        return jsonify({"error": "Rate limit exceeded. Please wait a moment."}), 429
    
    api_key = request.args.get('key')
    query = request.args.get('query')
    
    if not api_key or not query:
        return jsonify({"error": "Missing parameters! Usage: /api/v1/info?key=YOUR_KEY&query=TARGET_DATA"}), 400
    
    keys = get_keys()
    custom_apis = get_custom_apis()
    
    if api_key not in keys:
        log_error("INVALID_KEY", f"Invalid key used: {api_key}", api_key, query)
        return jsonify({"error": "Invalid API Key!"}), 401
    
    if settings.get('blacklist_enabled', True):
        blacklist = get_blacklist()
        if api_key in blacklist.get('keys', []):
            return jsonify({"error": "API Key has been revoked."}), 403
    
    key_info = keys[api_key]
    
    if date.today() > datetime.strptime(key_info.get('expiry_date', '2099-12-31'), '%Y-%m-%d').date():
        log_error("EXPIRED_KEY", f"Expired key used: {api_key}", api_key, query)
        return jsonify({"error": "API Key Expired! Contact Admin."}), 403
        
    if key_info['limit'] != 0 and key_info['used'] >= key_info['limit']:
        return jsonify({"error": "Daily Limit Reached!"}), 429

    api_type = key_info['api_type']
    
    # Check if it's a custom API
    if api_type in custom_apis:
        base_url = custom_apis[api_type]
    else:
        base_url = settings.get(f'{api_type}_api', '')
    
    if not base_url:
        return jsonify({"error": f"API endpoint '{api_type}' is not configured."}), 500

    if request.host in base_url:
        log_error("CONFIG_ERROR", "Self-referencing API configuration", api_key, query)
        return jsonify({
            "error": "CRITICAL CONFIG ERROR: You pasted your OWN API link in the settings! Please restore the original backend API link."
        }), 500

    url = base_url + query
    
    cache_key = f"{api_key}:{query}"
    if settings.get('cache_enabled', True) and cache_key in cache_store:
        cache_data, cache_time = cache_store[cache_key]
        if time.time() - cache_time < settings.get('cache_duration', 300):
            keys[api_key]['used'] += 1
            save_data(KEYS_FILE, keys)
            return jsonify(cache_data)
    
    try:
        resp = requests.get(url, timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if 'text/html' in resp.headers.get('Content-Type', ''):
            log_error("HTML_RESPONSE", "Backend returned HTML", api_key, query)
            return jsonify({
                "error": "Backend Source API is returning HTML instead of JSON. The original API might be blocked or offline.",
                "backend_url_tested": url
            }), 502

        if resp.status_code == 200:
            try:
                data = resp.json()
                
                # Remove old credits
                for f in ['credit', 'developer', 'owner', 'powered_by', 'api_by', 'BUY_API', 'SUPPORT', 'author', 'created_by']:
                    data.pop(f, None)
                
                # Add credits if enabled
                if settings.get('enable_credit', True):
                    data['credit'] = "@Aditya_dark0"
                    data['BUY_API'] = "@Aditya_dark0"
                    data['developed_by'] = "@Aditya_dark0"
                
                data['api_version'] = VERSION
                data['server_time'] = datetime.now().isoformat()
                data['api_name'] = API_NAME
                
                if settings.get('cache_enabled', True):
                    cache_store[cache_key] = (data.copy(), time.time())
                
                keys[api_key]['used'] += 1
                save_data(KEYS_FILE, keys)
                
                if settings.get('enable_logging', True):
                    update_analytics(
                        api_key,
                        key_info['api_type'],
                        "success",
                        client_ip,
                        request.headers.get('User-Agent')
                    )
                
                return jsonify(data)
                
            except json.JSONDecodeError:
                log_error("JSON_ERROR", "Invalid JSON from backend", api_key, query)
                return jsonify({"error": "Backend API Data is Corrupted (Not valid JSON)."}), 502
                
        log_error("HTTP_ERROR", f"Backend returned {resp.status_code}", api_key, query)
        return jsonify({"error": f"Original API Down (HTTP Code: {resp.status_code})"}), 502
        
    except requests.exceptions.RequestException as e:
        log_error("CONNECTION_ERROR", str(e), api_key, query)
        return jsonify({"error": f"Failed to connect to Source API: {str(e)}"}), 504

# ==========================================
# 📊 ANALYTICS ENDPOINTS
# ==========================================

@app.route('/api/analytics')
@admin_required
def get_analytics_endpoint():
    return jsonify(get_analytics())

@app.route('/api/keys/stats')
@admin_required
def get_key_stats():
    keys = get_keys()
    stats = {
        "total": len(keys),
        "active": 0,
        "expired": 0,
        "by_type": {}
    }
    for k, v in keys.items():
        if date.today() <= datetime.strptime(v['expiry_date'], '%Y-%m-%d').date():
            stats["active"] += 1
        else:
            stats["expired"] += 1
        api_type = v['api_type']
        if api_type not in stats["by_type"]:
            stats["by_type"][api_type] = 0
        stats["by_type"][api_type] += 1
    return jsonify(stats)

# ==========================================
# 🛡️ ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found. Use /api/v1/info"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

# ==========================================
# 🚀 EXECUTION LOGIC
# ==========================================

if __name__ == "__main__":
    print("="*70)
    print("🔥 ADITYA API HUB v2.0")
    print("="*70)
    print("🌍 Server: http://0.0.0.0:5000")
    print("🔑 Admin Password: 1q2w3e4r5t#Yt")
    print("📊 Analytics: Enabled")
    print("🛡️ Rate Limiting: Active")
    print("⚡ Cache: Enabled")
    print("🔧 Custom APIs: Supported")
    print("💎 Credits: @Aditya_dark0")
    print("="*70)
    
    app.run(host='0.0.0.0', port=5099, debug=False, threaded=True)