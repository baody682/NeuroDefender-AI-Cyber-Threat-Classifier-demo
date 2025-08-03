import os
import sys
import uuid
import datetime
import numpy as np
import pandas as pd
import joblib
from bs4 import BeautifulSoup
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, session, jsonify
from werkzeug.utils import secure_filename
from collections import Counter, deque
import json
import smtplib
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging
import time
import subprocess

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Flask App Initialization ---
app = Flask(__name__)
# Use a strong, random key in production. Get from environment or use a secure fallback.
app.secret_key = os.getenv("FLASK_SECRET_KEY", "A_VERY_STRONG_FALLBACK_KEY_BUT_CHANGE_THIS_IN_PROD_2025_RANDOM_STRING_XYZABC123")
if os.getenv("FLASK_SECRET_KEY") is None:
    logger.warning("FLASK_SECRET_KEY environment variable is not set. Using a strong fallback, but this should be set in production for security!")

# --- Database setup - Placeholder for actual database integration ---
# For production, replace this with SQLAlchemy and a proper database like PostgreSQL or MySQL
MOCK_DATABASE_USERS = {
    'admin': {'password': generate_password_hash('password123'), 'role': 'admin'},
    'analyst': {'password': generate_password_hash('analyst123'), 'role': 'analyst'},
    'viewer': {'password': generate_password_hash('viewer123'), 'role': 'viewer'}
}
users = MOCK_DATABASE_USERS # Alias for clarity in routes

# --- Email Configuration ---
EMAIL_ENABLED = True
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_SMTP_PORT = 587
EMAIL_USERNAME = "bodymahboub.eg@gmail.com" # Your sender email
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD") # Keep this as environment variable for security
EMAIL_TO = os.getenv("EMAIL_TO_ADDRESS", "your_alert_email@example.com") # Default recipient

if not EMAIL_PASSWORD:
    logger.warning("EMAIL_PASSWORD environment variable not set. Email alerts will not function.")
    EMAIL_ENABLED = False
if not EMAIL_TO:
    logger.warning("EMAIL_TO_ADDRESS environment variable not set. Email alerts will not function.")
    EMAIL_ENABLED = False

def send_email_alert(subject, body):
    """Sends a single email alert."""
    if not EMAIL_ENABLED:
        logger.info("Email alerts are disabled.")
        return False
    if not EMAIL_PASSWORD or not EMAIL_TO:
        logger.error("Cannot send email: EMAIL_PASSWORD or EMAIL_TO is not set.")
        return False

    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USERNAME
        msg['To'] = EMAIL_TO
        with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USERNAME, EMAIL_TO, msg.as_string())
        logger.info(f"Email alert sent: '{subject}' to {EMAIL_TO}")
        return True
    except Exception as e:
        logger.error(f"[!] Email alert failed: {e}", exc_info=True)
        return False

# --- Model Loading ---
model = None
scaler = None
label_encoder = None
# Paths to your trained model, scaler, and label encoder
MODEL_PATH = 'cyber_threat_model.pkl'
SCALER_PATH = 'scaler.pkl'
LABEL_ENCODER_PATH = 'label_encoder.pkl'

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    logger.info("Machine learning model components loaded successfully.")
except FileNotFoundError as e:
    logger.error(f"Error loading model files: {e}. Please ensure '{MODEL_PATH}', '{SCALER_PATH}', and '{LABEL_ENCODER_PATH}' are in the same directory.", exc_info=True)
    sys.exit(1) # Exit if models are crucial and not found
except Exception as e:
    logger.error(f"An unexpected error occurred while loading model files: {e}", exc_info=True)
    sys.exit(1) # Exit on other loading errors

# --- Expected Features (69 features as per your request) ---
# This list MUST match the features your model was trained on, in the correct order.
# And should align with the output of CICFlowMeter after processing.
EXPECTED_COLUMNS = [
    'destination_port', # Added as per your request
    'flow_duration', 'total_fwd_packets', 'total_backward_packets',
    'total_length_of_fwd_packets', 'total_length_of_bwd_packets',
    'fwd_packet_length_max', 'fwd_packet_length_min',
    'fwd_packet_length_mean', 'fwd_packet_length_std',
    'bwd_packet_length_max', 'bwd_packet_length_min',
    'bwd_packet_length_mean', 'bwd_packet_length_std',
    'flow_bytes_s', 'flow_packets_s', 'flow_iat_mean',
    'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'fwd_iat_total',
    'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
    'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max',
    'bwd_iat_min', 'fwd_psh_flags', 'fwd_urg_flags',
    'fwd_header_length', 'bwd_header_length',
    'fwd_packets_s', 'bwd_packets_s', 'min_packet_length',
    'max_packet_length', 'packet_length_mean', 'packet_length_std',
    'packet_length_variance', 'fin_flag_count', 'syn_flag_count',
    'rst_flag_count', 'psh_flag_count', 'ack_flag_count',
    'urg_flag_count', 'cwe_flag_count', 'ece_flag_count',
    'down_up_ratio', 'average_packet_size',
    'avg_fwd_segment_size', 'avg_bwd_segment_size',
    'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets',
    'subflow_bwd_bytes', 'init_win_bytes_forward',
    'init_win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward','active_mean',
    'active_std', 'active_max', 'active_min', 'idle_mean', 'idle_std',
    'idle_max', 'idle_min'
]

# Columns from CICFlowMeter output that are useful for debugging/display but not directly for model prediction
INFO_COLUMNS = ['flow_id', 'source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol', 'timestamp']

# Aliases for common CICFlowMeter column names (handling variations)
column_aliases = {
    'destination_port': ['dst_port', 'destination port', 'dport', 'Dst Port'],
    'flow_duration': ['duration', 'flow duration', 'Flow Duration'],
    'total_fwd_packets': ['total_fwd_packets', 'total_forward_packets', 'Total Fwd Packet'],
    'total_backward_packets': ['total_backward_packets', 'total_bwd_packets', 'Total Bwd packets'],
    'total_length_of_fwd_packets': ['total_length_of_fwd_packets', 'fwd_pkt_len_total', 'totlen_fwd_pkts', 'Total Length of Fwd Packet'],
    'total_length_of_bwd_packets': ['total_length_of_bwd_packets', 'bwd_pkt_len_total', 'totlen_bwd_pkts', 'Total Length of Bwd Packet'],
    'fwd_packet_length_max': ['fwd_pkt_len_max', 'Fwd Packet Length Max'],
    'fwd_packet_length_min': ['fwd_pkt_len_min', 'Fwd Packet Length Min'],
    'fwd_packet_length_mean': ['fwd_pkt_len_mean', 'Fwd Packet Length Mean'],
    'fwd_packet_length_std': ['fwd_pkt_len_std', 'Fwd Packet Length Std'],
    'bwd_packet_length_max': ['bwd_pkt_len_max', 'Bwd Packet Length Max'],
    'bwd_packet_length_min': ['bwd_pkt_len_min', 'Bwd Packet Length Min'],
    'bwd_packet_length_mean': ['bwd_pkt_len_mean', 'Bwd Packet Length Mean'],
    'bwd_packet_length_std': ['bwd_pkt_len_std', 'Bwd Packet Length Std'],
    'flow_bytes_s': ['flow_bytes/s', 'flow_byts/s', 'Flow Bytes/s'],
    'flow_packets_s': ['flow_pkts/s', 'Flow Packets/s'],
    'flow_iat_mean': ['flow_iat_mean', 'Flow IAT Mean'],
    'flow_iat_std': ['flow_iat_std', 'Flow IAT Std'],
    'flow_iat_max': ['flow_iat_max', 'Flow IAT Max'],
    'flow_iat_min': ['flow_iat_min', 'Flow IAT Min'],
    'fwd_iat_total': ['fwd_iat_total', 'Fwd IAT Total'],
    'fwd_iat_mean': ['fwd_iat_mean', 'Fwd IAT Mean'],
    'fwd_iat_std': ['fwd_iat_std', 'Fwd IAT Std'],
    'fwd_iat_max': ['fwd_iat_max', 'Fwd IAT Max'],
    'fwd_iat_min': ['fwd_iat_min', 'Fwd IAT Min'],
    'bwd_iat_total': ['bwd_iat_total', 'Bwd IAT Total'],
    'bwd_iat_mean': ['bwd_iat_mean', 'Bwd IAT Mean'],
    'bwd_iat_std': ['bwd_iat_std', 'Bwd IAT Std'],
    'bwd_iat_max': ['bwd_iat_max', 'Bwd IAT Max'],
    'bwd_iat_min': ['bwd_iat_min', 'Bwd IAT Min'],
    'fwd_psh_flags': ['fwd_psh_flags', 'Fwd PSH Flags'],
    'fwd_urg_flags': ['fwd_urg_flags', 'Fwd URG Flags'],
    'fwd_header_length': ['fwd_header_length', 'fwd_hdr_len', 'Fwd Header Length'],
    'bwd_header_length': ['bwd_header_length', 'bwd_hdr_len', 'Bwd Header Length'],
    'fwd_packets_s': ['fwd_pkts/s', 'Fwd Packets/s'],
    'bwd_packets_s': ['bwd_pkts/s', 'Bwd Packets/s'],
    'min_packet_length': ['min_pkt_len', 'Packet Length Min'],
    'max_packet_length': ['max_pkt_len', 'Packet Length Max'],
    'packet_length_mean': ['pkt_len_mean', 'Packet Length Mean'],
    'packet_length_std': ['pkt_len_std', 'Packet Length Std'],
    'packet_length_variance': ['pkt_len_var', 'Packet Length Variance'],
    'fin_flag_count': ['fin_flag_cnt', 'FIN Flag Count'],
    'syn_flag_count': ['syn_flag_cnt', 'SYN Flag Count'],
    'rst_flag_count': ['rst_flag_cnt', 'RST Flag Count'],
    'psh_flag_count': ['psh_flag_cnt', 'PSH Flag Count'],
    'ack_flag_count': ['ack_flag_cnt', 'ACK Flag Count'],
    'urg_flag_count': ['urg_flag_cnt', 'URG Flag Count'],
    'cwe_flag_count': ['cwe_flag_cnt', 'CWR Flag Count'],
    'ece_flag_count': ['ece_flag_cnt', 'ECE Flag Count'],
    'down_up_ratio': ['down/up_ratio', 'Down/Up Ratio'],
    'average_packet_size': ['avg_pkt_size', 'Average Packet Size'], # Included as per 69 column list
    'avg_fwd_segment_size': ['avg_fwd_seg_size', 'Fwd Segment Size Avg'],
    'avg_bwd_segment_size': ['avg_bwd_seg_size', 'Bwd Segment Size Avg'],
    # Removed as per 69 column list: 'fwd_avg_bytes_bulk', 'fwd_avg_packets_bulk', 'fwd_avg_bulk_rate',
    # Removed as per 69 column list: 'bwd_avg_bytes_bulk', 'bwd_avg_packets_bulk', 'bwd_avg_bulk_rate',
    'subflow_fwd_packets': ['subflow_fwd_pkts', 'Subflow Fwd Packets'],
    'subflow_fwd_bytes': ['subflow_fwd_byts', 'Subflow Fwd Bytes'],
    'subflow_bwd_packets': ['subflow_bwd_pkts', 'Subflow Bwd Packets'],
    'subflow_bwd_bytes': ['subflow_bwd_byts', 'Subflow Bwd Bytes'],
    'init_win_bytes_forward': ['init_win_bytes_fwd', 'FWD Init Win Bytes'],
    'init_win_bytes_backward': ['init_win_bytes_bwd', 'Bwd Init Win Bytes'],
    'act_data_pkt_fwd': ['act_data_pkt_fwd', 'Fwd Act Data Pkts'],
    # Removed as per 69 column list: 'min_fl_fwd_iat', 'max_fl_fwd_iat', 'mean_fl_fwd_iat', 'std_fl_fwd_iat',
    'min_seg_size_forward': ['min_seg_size_forward', 'Fwd Seg Size Min'], # Corrected alias based on the 69 columns
    'active_mean': ['active_mean', 'Active Mean'],
    'active_std': ['active_std', 'Active Std'],
    'active_max': ['active_max', 'Active Max'],
    'active_min': ['active_min', 'Active Min'],
    'idle_mean': ['idle_mean', 'Idle Mean'],
    'idle_std': ['idle_std', 'Idle Std'],
    'idle_max': ['idle_max', 'Idle Max'],
    'idle_min': ['idle_min', 'Idle Min']
}


# Get known classes from the label encoder, if loaded
known_classes = set(label_encoder.classes_) if label_encoder else set()
if not known_classes:
    logger.warning("Label encoder not loaded, known_classes set to empty. Anomaly detection based on unknown classes will not function.")

# --- Real-time Dashboard Data Structures ---
dashboard_stats = {
    "total_packets": 0, # Renamed from flow_count for clarity based on general "packets"
    "threat_distribution": Counter(), # e.g., {'Benign': 100, 'Malware': 5}
    "alerts": deque(maxlen=50), # Store recent alerts for display
    "alerts_over_time": deque(maxlen=60) # Store (timestamp, count) for last 60 minutes/intervals
}

# --- Utility Functions ---
def require_role(*roles):
    """Decorator to restrict access to routes based on user roles."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'user' not in session or 'role' not in session:
                flash("You must be logged in to access this page.", "warning")
                return redirect(url_for('login'))
            if session['role'] not in roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('index')) # Redirect to a generic page or error page
            return f(*args, **kwargs)
        return wrapper
    return decorator

def process_pcap_with_cicflow(pcap_filepath, output_dir):
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = os.path.splitext(os.path.basename(pcap_filepath))[0]
    output_csv_filename = f"{base_filename}_cicflow_{timestamp_str}.csv"
    output_csv_filepath = os.path.join(output_dir, output_csv_filename)

    logger.info(f"Attempting to process PCAP: {pcap_filepath} using cicflow_processor.py")
    try:
        command = [
            sys.executable, # Use the current Python interpreter
            'cicflow_processor.py',
            '--input', pcap_filepath,
            '--output', output_csv_filepath # Pass the desired output CSV path
        ]
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        logger.info(f"cicflow_processor.py stdout: {result.stdout}")
        if result.stderr:
            logger.warning(f"cicflow_processor.py stderr: {result.stderr}")

        if os.path.exists(output_csv_filepath) and os.path.getsize(output_csv_filepath) > 0:
            logger.info(f"PCAP successfully processed to CSV: {output_csv_filepath}")
            return output_csv_filepath
        else:
            logger.error(f"cicflow_processor.py did not produce a valid output CSV at {output_csv_filepath}")
            return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running cicflow_processor.py for {pcap_filepath}: {e}", exc_info=True)
        logger.error(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        logger.error("cicflow_processor.py not found. Ensure it's in the same directory or accessible via PATH.", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during PCAP processing: {e}", exc_info=True)
        return None


def standardize_columns(df):
    """
    Standardizes DataFrame column names to match expected_columns,
    handling aliases and adding missing columns with default values.
    """
    logger.debug(f"Initial columns before standardization: {df.columns.tolist()}")
    
    # Clean column names first (lowercase, replace spaces/slashes/dots with underscores)
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_").str.replace("/", "_").str.replace(".", "_")
    logger.debug(f"Columns after initial cleaning: {df.columns.tolist()}")
    
    col_map = {}
    # Create a reverse map for quick lookup: cleaned_alias -> expected_column_name
    reverse_alias_map = {}
    for expected_col, aliases in column_aliases.items():
        for alias in aliases:
            cleaned_alias = alias.strip().lower().replace(" ", "_").replace("/", "_").replace(".", "_")
            reverse_alias_map[cleaned_alias] = expected_col

    current_cols_set = set(df.columns)
    
    # Identify columns to rename or add
    for expected_col in EXPECTED_COLUMNS:
        if expected_col not in current_cols_set:
            # Check if any alias for this expected_col exists in current DataFrame
            found_alias_for_expected = False
            if expected_col in column_aliases:
                for alias in column_aliases[expected_col]:
                    cleaned_alias = alias.strip().lower().replace(" ", "_").replace("/", "_").replace(".", "_")
                    if cleaned_alias in current_cols_set and cleaned_alias not in col_map.keys(): # Prevent re-mapping if already mapped
                        col_map[cleaned_alias] = expected_col
                        logger.info(f"Renaming column '{cleaned_alias}' to '{expected_col}'.")
                        found_alias_for_expected = True
                        break
            
            if not found_alias_for_expected:
                # If column is still missing after checking aliases, add it with 0.0
                df[expected_col] = 0.0
                logger.debug(f"Added missing column '{expected_col}' with default value 0.0.")

    # Apply renaming if any aliases were found
    if col_map:
        df.rename(columns=col_map, inplace=True)
        logger.debug(f"Columns after renaming aliases: {df.columns.tolist()}")
    
    # Ensure all expected columns are present (after renaming) and in the correct order
    # Drop any extra columns that are not in EXPECTED_COLUMNS
    final_df_columns = []
    for col in EXPECTED_COLUMNS:
        if col in df.columns:
            final_df_columns.append(col)
        else:
            # This case should ideally not happen if the above logic is correct,
            # but as a safeguard, add it with 0.0 if still missing
            df[col] = 0.0
            final_df_columns.append(col)
            logger.warning(f"Column '{col}' was still missing after standardization and aliases, added with 0.0.")

    return df[final_df_columns]

def allowed_file(filename):
    """Checks if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def predict_flow(features_df):
    """
    Performs prediction on a DataFrame of features using the loaded model components.
    Handles data scaling and inverse transformation of predictions.
    """
    if model is None or scaler is None or label_encoder is None:
        logger.error("Model components are not loaded. Cannot predict flow.")
        return "Model_Error", 0.0 # Return a default label and probability

    # Ensure all expected columns are present and in the correct order
    # This should largely be handled by standardize_columns before calling predict_flow
    features_df = features_df[EXPECTED_COLUMNS] 
    
    # Handle infinite values and NaNs gracefully before scaling
    features_df = features_df.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    try:
        df_scaled = scaler.transform(features_df)
        prediction_array = model.predict(df_scaled)
        
        # Get probabilities if the model supports it
        probabilities = None
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(df_scaled)
            # Find the probability for the predicted class
            predicted_class_idx = prediction_array[0]
            probability_of_prediction = probabilities[0, predicted_class_idx]
        else:
            probability_of_prediction = 1.0 # Default if no proba available

        label = label_encoder.inverse_transform(prediction_array)[0]
        return label, probability_of_prediction
    except Exception as e:
        logger.error(f"Error during prediction: {e}", exc_info=True)
        return "Prediction_Error", 0.0

# --- File Storage Configuration ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'pcap', 'pcapng'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 30 * 1024 * 1024  # 30 MB limit for uploads

os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Ensure upload folder exists

HISTORY_CSV = os.path.join(UPLOAD_FOLDER, 'analysis_history.csv') # Dedicated history file

# --- Translation Strings ---
translations = {
    'ar': {
        'title': "نظام تصنيف الهجمات السيبرانية",
        'upload_label': "يرجى رفع ملف البيانات بصيغة CSV",
        'upload_button': "تحليل",
        'results_title': "نتائج التحليل",
        'download_btn': "تحميل النتائج",
        'search_placeholder': "ابحث عن اسم الملف...",
        'show_more': "عرض المزيد من الصفوف",
        'login_title': "تسجيل الدخول",
        'username_label': "اسم المستخدم",
        'password_label': "كلمة المرور",
        'login_button': "تسجيل الدخول",
        'no_account': "ليس لديك حساب؟",
        'signup_link': "إنشاء حساب",
        'signup_title': "إنشاء حساب",
        'signup_button': "إنشاء حساب",
        'already_account': "لديك حساب بالفعل؟",
        'login_link': "تسجيل الدخول",
        'logout_link': "تسجيل الخروج",
        'dashboard_link': "لوحة التحكم",
        'manage_users_link': "إدارة المستخدمين",
        'clear_history_button': "مسح السجل",
        'file_history_title': "سجل الملفات المحللة",
        'filename_col': "اسم الملف",
        'date_col': "التاريخ",
        'actions_col': "الإجراءات",
        'download_action': "تحميل",
        'dashboard_flow_count': "إجمالي التدفقات",
        'dashboard_threat_counts': "توزيع التهديدات",
        'dashboard_recent_alerts': "التنبيهات الأخيرة",
        'dashboard_label': "النوع",
        'dashboard_alert': "التنبيه",
        'dashboard_timestamp': "الوقت",
        'dashboard_normal': "عادي",
        'dashboard_anomaly_detected': "تم اكتشاف شذوذ",
        'dashboard_unknown': "غير معروف",
        'account_created': "تم إنشاء الحساب بنجاح",
        'username_exists': "اسم المستخدم موجود بالفعل.",
        'invalid_credentials': "اسم المستخدم أو كلمة المرور غير صحيحة",
        'username_too_short': "يجب أن يتكون اسم المستخدم من 3 أحرف على الأقل.",
        'password_too_short': "يجب أن تتكون كلمة المرور من 6 أحرف على الأقل.",
        'user_added': "تم إضافة المستخدم {username} بالدور {role}.",
        'cannot_delete_admin': "لا يمكن حذف المستخدم المسؤول.",
        'cannot_delete_self': "لا يمكن حذف حسابك الخاص أثناء تسجيل الدخول.",
        'user_deleted': "تم حذف المستخدم {username}.",
        'user_not_found': "المستخدم غير موجود.",
        'role_updated': "تم تحديث دور {username} إلى {new_role}.",
        'user_not_found_or_admin': "المستخدم غير موجود أو لا يمكن تغيير دور المسؤول.",
        'invalid_role': "الدور المحدد غير صالح.",
        'no_upload_permission': "ليس لديك إذن لرفع الملفات.",
        'no_file_selected': "لم يتم اختيار ملف.",
        'invalid_file_type': "نوع الملف غير صالح. يُسمح بملفات CSV فقط.",
        'no_valid_data': "الملف الذي تم رفعه لا يحتوي على بيانات صالحة بعد المعالجة المسبقة.",
        'model_not_loaded': "نموذج التعلم الآلي غير محمل. لا يمكن إجراء التحليل.",
        'csv_parse_error': "خطأ في تحليل ملف CSV. يرجى التأكد من أنه ملف CSV صالح: {error}",
        'file_processing_error': "خطأ في معالجة الملف: {error}",
        'clear_history_success': "تم مسح السجل بنجاح",
        'clear_history_error': "خطأ أثناء مسح السجل: {error}",
        'no_history_file': "لا يوجد ملف سجل للمسح.",
        'logout_success': "تم تسجيل الخروج بنجاح.",
    },
    'en': {
        'title': "Cyber Threat Classification System",
        'upload_label': "Please upload the CSV file",
        'upload_button': "Analyze",
        'results_title': "Analysis Results",
        'download_btn': "Download Results",
        'search_placeholder': "Search file name...",
        'show_more': "Show more rows",
        'login_title': "Login",
        'username_label': "Username",
        'password_label': "Password",
        'login_button': "Login",
        'no_account': "Don't have an account?",
        'signup_link': "Sign Up",
        'signup_title': "Sign Up",
        'signup_button': "Create Account",
        'already_account': "Already have an account?",
        'login_link': "Login",
        'logout_link': "Logout",
        'dashboard_link': "Dashboard",
        'manage_users_link': "Manage Users",
        'clear_history_button': "Clear History",
        'file_history_title': "Analyzed File History",
        'filename_col': "File Name",
        'date_col': "Date",
        'actions_col': "Actions",
        'download_action': "Download",
        'dashboard_flow_count': "Total Flows",
        'dashboard_threat_counts': "Threat Distribution",
        'dashboard_recent_alerts': "Recent Alerts",
        'dashboard_label': "Label",
        'dashboard_alert': "Alert",
        'dashboard_timestamp': "Timestamp",
        'dashboard_normal': "Normal",
        'dashboard_anomaly_detected': "Anomaly Detected",
        'dashboard_unknown': "Unknown",
        'account_created': "Account created successfully.",
        'username_exists': "Username already exists.",
        'invalid_credentials': "Invalid username or password",
        'username_too_short': "Username must be at least 3 characters.",
        'password_too_short': "Password must be at least 6 characters.",
        'user_added': "User {username} added with role {role}.",
        'cannot_delete_admin': "Cannot delete admin user.",
        'cannot_delete_self': "Cannot delete your own account while logged in.",
        'user_deleted': "User {username} deleted.",
        'user_not_found': "User not found.",
        'role_updated': "Role for {username} updated to {new_role}.",
        'user_not_found_or_admin': "User not found or cannot change admin role.",
        'invalid_role': "Invalid role selected.",
        'no_upload_permission': "You do not have permission to upload files.",
        'no_file_selected': "No file selected.",
        'invalid_file_type': "Invalid file type. Only CSV files are allowed.",
        'no_valid_data': "The uploaded file contains no valid data after preprocessing.",
        'model_not_loaded': "Machine learning model not loaded. Cannot perform analysis.",
        'csv_parse_error': "Error parsing CSV file. Please ensure it's a valid CSV: {error}",
        'file_processing_error': "Error processing file: {error}",
        'clear_history_success': "History cleared successfully",
        'clear_history_error': "Error clearing history: {error}",
        'no_history_file': "No history file to clear.",
        'logout_success': "You have been logged out.",
    }
}

# --- Routes ---

@app.route('/')
@require_role('admin', 'analyst', 'viewer')
def index():
    if 'user' not in session:
        return redirect(url_for('login', lang=request.args.get('lang', 'ar')))

    lang = request.args.get('lang', 'ar')
    strings = translations.get(lang, translations['ar'])

    table_html = None
    download_link = None
    history = []
    threat_counts_json = None

    user_logged_in = 'user' in session
    user_role = session.get('role', '')

    can_upload = user_role in ['admin', 'analyst']
    can_clear = user_role == 'admin'

    # Load history for display on initial page load
    if os.path.exists(HISTORY_CSV):
        try:
            history_df = pd.read_csv(HISTORY_CSV)
            # Ensure 'result_file' exists for older entries if needed, or default it
            if 'result_file' not in history_df.columns:
                history_df['result_file'] = history_df['filename'].apply(lambda f: f"results_{uuid.uuid4().hex[:8]}.csv") # Dummy for old entries
            history = history_df.to_dict(orient='records')
        except pd.errors.EmptyDataError:
            history = []
        except Exception as e:
            logger.error(f"Error loading history.csv for display: {e}", exc_info=True)
            history = []

    return render_template(
        'index.html',
        lang=lang,
        strings=strings,
        table=table_html, # Will be filled after POST request
        download_link=download_link, # Will be filled after POST request
        history=history,
        sidebar_open=True, # Assuming sidebar is open by default
        threat_counts=threat_counts_json, # Will be filled after POST request
        user_logged_in=user_logged_in,
        user_role=user_role,
        can_upload=can_upload,
        can_clear=can_clear
    )

@app.route('/', methods=['POST'])
@require_role('admin', 'analyst') # Only admin/analyst can upload files
def upload_file_for_analysis():
    lang = request.args.get('lang', 'ar')
    strings = translations.get(lang, translations['ar'])
    user_role = session.get('role', '')
    user_logged_in = 'user' in session

    if not (user_role in ['admin', 'analyst']):
        flash(strings.get('no_upload_permission', "You do not have permission to upload files."))
        logger.warning(f"User {session.get('user')} attempted unauthorized file upload.")
        return redirect(url_for('index', lang=lang))

    file = request.files.get('file')
    if not file or file.filename == '':
        flash(strings.get('no_file_selected', "No file selected"))
        return redirect(request.url)

    if not allowed_file(file.filename):
        flash(strings.get('invalid_file_type', "Invalid file type. Only CSV, PCAP, PCAPNG files are allowed.")) # Update message
        return redirect(request.url)

    table_html = None
    download_link = None
    threat_counts_json = None
    can_upload = user_role in ['admin', 'analyst']
    can_clear = user_role == 'admin'
    
    filename = secure_filename(file.filename)
    original_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(original_filepath)
    logger.info(f"File '{filename}' uploaded by {session.get('user')}.")

    # Determine if it's a PCAP or CSV
    is_pcap = filename.lower().endswith(('.pcap', '.pcapng'))
    
    filepath_to_analyze = original_filepath # Default to original if it's a CSV
    
    if is_pcap:
        logger.info(f"Detected PCAP file: {filename}. Sending for CICFlowMeter processing.")
        # Call the function to process PCAP
        generated_csv_filepath = process_pcap_with_cicflow(original_filepath, app.config['UPLOAD_FOLDER'])
        
        if generated_csv_filepath:
            filepath_to_analyze = generated_csv_filepath
            # Optional: Remove the original PCAP file after processing if you don't need to keep it
            # os.remove(original_filepath)
            # logger.info(f"Removed temporary PCAP file: {original_filepath}")
        else:
            flash(strings.get('file_processing_error', f"Error processing PCAP file with CICFlowMeter. Check server logs."))
            logger.error(f"Failed to convert PCAP {filename} to CSV.")
            # Ensure all variables are defined for render_template in case of early exit
            history = [] # Initialize history
            return render_template(
                'index.html',
                lang=lang,
                strings=strings,
                table=table_html,
                download_link=download_link,
                history=history,
                sidebar_open=True,
                threat_counts=threat_counts_json,
                user_logged_in=user_logged_in,
                user_role=user_role,
                can_upload=can_upload,
                can_clear=can_clear
            )

    try:
        df = pd.read_csv(filepath_to_analyze)
        logger.debug(f"DataFrame loaded from CSV (after potential PCAP conversion). Shape: {df.shape}, Columns: {df.columns.tolist()}")

        # Attempt to drop 'Label' or 'label' column if it exists (CICFlowMeter might add it)
        # Ensure 'Prediction' column is not mistaken for a feature if present
        features = df.drop(columns=['Label', 'label', 'Prediction'], axis=1, errors='ignore').copy()
        logger.debug(f"Features DataFrame after dropping 'Label'/'label'/'Prediction'. Shape: {features.shape}, Columns: {features.columns.tolist()}")

        features = standardize_columns(features)
        logger.debug(f"Features DataFrame after standardize_columns. Shape: {features.shape}, Columns: {features.columns.tolist()}")

        # Handle infinite values and NaNs gracefully before prediction
        features = features.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        
        if features.empty:
            flash(strings.get('no_valid_data', "The uploaded file contains no valid data after preprocessing."))
            logger.error("Features DataFrame is empty after preprocessing. Cannot proceed with analysis.")
            # Ensure all variables are defined for render_template in case of early exit
            history = [] # Initialize history
            return render_template(
                'index.html',
                lang=lang,
                strings=strings,
                table=table_html,
                download_link=download_link,
                history=history,
                sidebar_open=True,
                threat_counts=threat_counts_json,
                user_logged_in=user_logged_in,
                user_role=user_role,
                can_upload=can_upload,
                can_clear=can_clear
            )

        if model is None or scaler is None or label_encoder is None:
            flash(strings.get('model_not_loaded', "Machine learning model not loaded. Cannot perform analysis."))
            logger.error("Attempted analysis but ML models are not loaded. Check server startup logs.")
            history = [] # Initialize history
            return render_template(
                'index.html',
                lang=lang,
                strings=strings,
                table=table_html,
                download_link=download_link,
                history=history,
                sidebar_open=True,
                threat_counts=threat_counts_json,
                user_logged_in=user_logged_in,
                user_role=user_role,
                can_upload=can_upload,
                can_clear=can_clear
            )

        logger.debug(f"Attempting to scale features. Features shape: {features.shape}")
        features_scaled = scaler.transform(features)
        logger.debug(f"Features scaled successfully. Scaled features shape: {features_scaled.shape}")

        logger.debug("Attempting to predict labels.")
        predictions_array = model.predict(features_scaled)
        predicted_labels = label_encoder.inverse_transform(predictions_array)
        logger.debug(f"Predictions made. First 5 predicted labels: {predicted_labels[:5].tolist()}")

        df_results = df.loc[features.index].copy() # Ensure results align with processed features
        df_results['Prediction'] = predicted_labels
        # Determine anomaly status based on whether the prediction is in known_classes
        df_results['Anomaly'] = df_results['Prediction'].apply(lambda x: "🔝 Yes" if x not in known_classes else "✅ No")
        logger.debug(f"Results DataFrame created. Shape: {df_results.shape}, Columns: {df_results.columns.tolist()}")

        # Update dashboard stats from the uploaded file's analysis
        dashboard_stats["total_packets"] += len(df_results)
        dashboard_stats["threat_distribution"].update(Counter(predicted_labels))

        row_classes = ['anomaly-yes' if p not in known_classes else 'anomaly-no' for p in predicted_labels]

        # Use the name of the *original* uploaded file for history, but point to the results CSV
        result_filename_for_history = filename # This keeps the original name in history, though the downloadable file is the result CSV
        result_filename_actual = f"results_{uuid.uuid4().hex[:8]}.csv" # This is the actual name of the generated CSV
        result_filepath = os.path.join(app.config['UPLOAD_FOLDER'], result_filename_actual)
        df_results.to_csv(result_filepath, index=False)
        logger.info(f"Analysis results saved to '{result_filename_actual}'.")

        raw_html = df_results.to_html(classes='table table-bordered table-striped', index=False, escape=False)
        soup = BeautifulSoup(raw_html, 'html.parser')
        rows = soup.find_all('tr')
        data_rows = rows[1:] # Skip header row

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        # Store the actual result filename for download, but original for display
        entry = pd.DataFrame([{'filename': result_filename_for_history, 'date': timestamp, 'result_file': result_filename_actual}])

        if os.path.exists(HISTORY_CSV):
            try:
                history_df = pd.read_csv(HISTORY_CSV)
                # Ensure 'result_file' column exists for older entries
                if 'result_file' not in history_df.columns:
                    history_df['result_file'] = history_df['filename'].apply(lambda f: f"results_{uuid.uuid4().hex[:8]}.csv") # Placeholder for old entries, ideally regenerate or use consistent naming
                
                # Concatenate new entry and remove duplicates based on filename, keeping the latest.
                # Use 'result_file' for actual file uniqueness, 'filename' for display uniqueness
                history_df = pd.concat([entry, history_df], ignore_index=True).drop_duplicates('filename', keep='first')
            except pd.errors.EmptyDataError:
                history_df = entry # If file is empty, start with new entry
        else:
            history_df = entry # If file doesn't exist, create with new entry
        history_df.to_csv(HISTORY_CSV, index=False)
        logger.info(f"History updated with '{result_filename_for_history}' (results saved as '{result_filename_actual}').")

        for i, row in enumerate(data_rows):
            if 'class' not in row.attrs:
                row.attrs['class'] = []
            row.attrs['class'].append('data-row')
            if i < 10: # Only make first 10 rows visible initially
                row.attrs['class'].append('visible')
            row.attrs['class'].append(row_classes[i])

        table_html = str(soup)
        download_link = url_for('download_file', filename=result_filename_actual) # Point to the actual result file

        threat_counts = dict(Counter(predicted_labels))
        threat_counts_json = json.dumps(threat_counts, ensure_ascii=False)

        # Trigger email alerts for anomalies in uploaded file
        for idx, pred in enumerate(predicted_labels):
            if pred not in known_classes: # Anomaly detected
                # Attempt to get source/dest IP/port from the original row for better alerts
                original_row = df_results.iloc[idx]
                src_ip = original_row.get('Source IP', original_row.get('src_ip', 'N/A'))
                dst_port = original_row.get('Destination Port', original_row.get('destination_port', 'N/A'))
                
                alert_details = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "type": pred,
                    "source_ip": src_ip,
                    "destination_port": dst_port,
                    "file": filename, # Original uploaded filename
                    "row_index": idx + 1
                }
                dashboard_stats["alerts"].appendleft(alert_details) # Add to recent alerts
                
                subject = f"NeuroDefender ALERT (File Upload): {pred}"
                message = f"Anomaly detected in uploaded file '{filename}'!\nType: {pred}\nRow: {idx+1}\nSource IP: {src_ip}\nDestination Port: {dst_port}\nTime: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                send_email_alert(subject, message)
                logger.warning(f"File upload: Anomaly detected and alert sent for type: {pred}")

    except pd.errors.ParserError as e:
        flash(strings.get('csv_parse_error', f"Error parsing file (CSV or converted from PCAP). Please ensure it's valid: {str(e)}")) # Update message
        logger.error(f"File parsing error for '{filename if 'filename' in locals() else 'unknown'}': {e}", exc_info=True)
    except Exception as e:
        flash(strings.get('file_processing_error', f"Error processing file: {str(e)}"))
        logger.error(f"General error processing file '{filename if 'filename' in locals() else 'unknown'}': {e}", exc_info=True)
    
    # Reload history (potentially updated) and pass current stats for re-render
    history = []
    if os.path.exists(HISTORY_CSV):
        try:
            history_df = pd.read_csv(HISTORY_CSV)
            history = history_df.to_dict(orient='records')
        except pd.errors.EmptyDataError:
            history = []
        except Exception as e:
            logger.error(f"Error loading history.csv for display after POST: {e}", exc_info=True)
            history = []

    return render_template(
        'index.html',
        lang=lang,
        strings=strings,
        table=table_html,
        download_link=download_link,
        history=history,
        sidebar_open=True,
        threat_counts=threat_counts_json,
        user_logged_in=user_logged_in,
        user_role=user_role,
        can_upload=can_upload,
        can_clear=can_clear
    )



@app.route('/download/<filename>')
@require_role('admin', 'analyst', 'viewer')
def download_file(filename):
    lang = request.args.get('lang', 'en')
    strings = translations.get(lang, translations['en'])

    history_df = pd.DataFrame()
    if os.path.exists(HISTORY_CSV):
        try:
            history_df = pd.read_csv(HISTORY_CSV)
        except pd.errors.EmptyDataError:
            history_df = pd.DataFrame()
    
    if 'result_file' in history_df.columns and filename in history_df['result_file'].values:
        safe_filename = secure_filename(filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        if not os.path.exists(file_path):
            flash(strings.get('file_not_found', "File not found."))
            logger.warning(f"Download attempt for non-existent result file: {safe_filename} by {session.get('user')}")
            return redirect(url_for('index', lang=lang))
        logger.info(f"User {session.get('user')} downloading result file: {safe_filename}")
        return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename, as_attachment=True)
    else:
        flash(strings.get('file_not_found', "File not found or unauthorized access."), "danger")
        logger.warning(f"Unauthorized or invalid download attempt for filename: {filename} by {session.get('user')}")
        return redirect(url_for('index', lang=lang))

@app.route('/dashboard')
@require_role('admin', 'analyst', 'viewer')
def dashboard():
    """Renders the real-time dashboard page."""
    lang = request.args.get('lang', 'en')
    strings = translations.get(lang, translations['en'])
    user_logged_in = 'user' in session
    user_role = session.get('role', '')
    return render_template('dashboard.html',
                            lang=lang,
                            strings=strings,
                            user_logged_in=user_logged_in,
                            user_role=user_role,
                            sidebar_open=True) # Assume sidebar open by default

@app.route('/api/dashboard_stats')
@require_role('admin', 'analyst', 'viewer') # API also requires authentication
def api_dashboard_stats():
    current_alerts_for_json = list(dashboard_stats["alerts"])

    alerts_time_series_data = [
        {"time": ts.strftime("%H:%M:%S"), "count": count}
        for ts, count in dashboard_stats["alerts_over_time"]
    ]

    return jsonify({
        "total_packets": dashboard_stats["total_packets"],
        "threat_distribution": dict(dashboard_stats["threat_distribution"]), # Convert Counter to dict
        "alerts": current_alerts_for_json,
        "alerts_over_time": alerts_time_series_data
    })


@app.route('/api/process_cicflow_data', methods=['POST'])
def api_process_cicflow_data():
    if not request.is_json:
        logger.error("Request to /api/process_cicflow_data must be JSON.")
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    if not data or 'flows' not in data:
        logger.error("Invalid data format received at /api/process_cicflow_data. Expected 'flows' key.")
        return jsonify({"error": "Invalid data format. Expected 'flows' key."}), 400

    flows_data = data.get('flows', [])
    if not flows_data:
        logger.info("Received no flows to process via API.")
        return jsonify({"message": "No flows to process."}), 200

    processed_count = 0
    anomalies_detected_count = 0

    for flow_dict in flows_data:
        try:
            # Convert single flow dictionary to a DataFrame row
            features_df_single_row = pd.DataFrame([flow_dict])
            
            # Standardize columns to match the model's expected features
            features_df_single_row = standardize_columns(features_df_single_row)

            if features_df_single_row.empty:
                logger.warning("Skipping empty flow record received from API after standardization.")
                continue

            label, probability = predict_flow(features_df_single_row)
            
            alert_status = "ANOMALY DETECTED" if label not in known_classes else "Normal"

            dashboard_stats["total_packets"] += 1 # Increment total flows/packets
            dashboard_stats["threat_distribution"][label] += 1
            
            src_ip = flow_dict.get('source_ip', flow_dict.get('Src IP', 'N/A'))
            dst_ip = flow_dict.get('destination_ip', flow_dict.get('Dst IP', 'N/A'))
            src_port = flow_dict.get('source_port', flow_dict.get('Src Port', 'N/A'))
            dst_port = flow_dict.get('destination_port', flow_dict.get('Dst Port', 'N/A'))
            protocol = flow_dict.get('protocol', flow_dict.get('Protocol', 'N/A'))
            flow_id = flow_dict.get('flow_id', flow_dict.get('Flow ID', 'N/A'))

            current_time = datetime.datetime.now()
            alert_details = {
                "timestamp": current_time.isoformat(),
                "type": label,
                "alert": alert_status,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": protocol,
                "flow_id": flow_id,
                "prediction_probability": round(probability, 4) if probability else 'N/A'
            }
            dashboard_stats["alerts"].appendleft(alert_details) # Add to the beginning of deque

            logger.info(f"[+] API Flow Event: {label} - {alert_status} (SrcIP: {src_ip}, DstIP: {dst_ip}, DstPort: {dst_port})")
            
            if alert_status == "ANOMALY DETECTED":
                anomalies_detected_count += 1
                subject = f"NeuroDefender ALERT (Real-time Flow Anomaly): {label}"
                message = (f"Anomaly detected in real-time network flow!\n"
                           f"Type: {label}\n"
                           f"Source IP: {src_ip}\nDestination IP: {dst_ip}\n"
                           f"Source Port: {src_port}\nDestination Port: {dst_port}\n"
                           f"Protocol: {protocol}\n"
                           f"Flow ID: {flow_id}\n"
                           f"Time: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
                send_email_alert(subject, message)

            processed_count += 1

            current_minute_ts = current_time.replace(second=0, microsecond=0)
            if dashboard_stats["alerts_over_time"] and \
               dashboard_stats["alerts_over_time"][0][0] == current_minute_ts:
                # Update last entry's count
                timestamp_obj, count = dashboard_stats["alerts_over_time"].popleft()
                dashboard_stats["alerts_over_time"].appendleft((timestamp_obj, count + (1 if alert_status == "ANOMALY DETECTED" else 0)))
            else:
                # Add new entry for the current minute
                dashboard_stats["alerts_over_time"].appendleft((current_minute_ts, (1 if alert_status == "ANOMALY DETECTED" else 0)))

        except Exception as e:
            logger.error(f"Error processing flow received via API: {flow_dict} - {e}", exc_info=True)

    return jsonify({"ok": True, "processed_flows": processed_count, "anomalies_detected": anomalies_detected_count}), 200

@app.route('/clear_history', methods=['POST'])
@require_role('admin')
def clear_history():
    """Clears the file analysis history."""
    lang = request.args.get('lang', 'en')
    strings = translations.get(lang, translations['en'])

    if os.path.exists(HISTORY_CSV):
        try:
            os.remove(HISTORY_CSV)
            flash(strings.get('clear_history_success', "History cleared successfully"))
            logger.info(f"Admin {session.get('user')} cleared file history.")
        except Exception as e:
            flash(strings.get('clear_history_error', f"Error clearing history: {e}"))
            logger.error(f"Error clearing history.csv: {e}", exc_info=True)
    else:
        flash(strings.get('no_history_file', "No history file to clear."))
        logger.info("Attempted to clear history, but no history file found.")
    return redirect(url_for('index', lang=lang))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user registration."""
    lang = request.args.get('lang', 'en')
    strings = translations.get(lang, translations['en'])
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # New users default to 'viewer' role; admin can change later
        role = 'viewer' 

        if not username or len(username) < 3:
            flash(strings['username_too_short'])
            return redirect(url_for('signup', lang=lang))
        if not password or len(password) < 6:
            flash(strings['password_too_short'])
            return redirect(url_for('signup', lang=lang))

        if username in users:
            flash(strings['username_exists'])
            return redirect(url_for('signup', lang=lang))
        
        users[username] = {'password': generate_password_hash(password), 'role': role}
        flash(strings['account_created'])
        logger.info(f"New user signed up: {username} with role {role}.")
        return redirect(url_for('login', lang=lang))
    return render_template('signup.html', lang=lang, strings=strings)

@app.route('/logout')
def logout():
    """Handles user logout."""
    lang = request.args.get('lang', 'en')
    strings = translations.get(lang, translations['en'])
    user = session.get('user')
    session.pop('user', None)
    session.pop('role', None)
    flash(strings.get('logout_success', "You have been logged out."))
    logger.info(f"User {user} logged out.")
    return redirect(url_for('login', lang=lang))

@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login."""
    lang = request.args.get('lang', 'en')
    strings = translations.get(lang, translations['en'])
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = users.get(username) # Renamed to user_data to avoid conflict with 'user' in session

        if user_data and check_password_hash(user_data['password'], password):
            session['user'] = username
            session['role'] = user_data['role']
            logger.info(f"User {username} logged in successfully with role {user_data['role']}.")
            return redirect(url_for('index', lang=lang))
        else:
            flash(strings['invalid_credentials'])
            logger.warning(f"Failed login attempt for user: {username}.")
            return redirect(url_for('login', lang=lang))
    return render_template("login.html", lang=lang, strings=strings)


@app.route('/users', methods=['GET', 'POST'])
@require_role('admin')
def manage_users():
    """Admin route for managing users."""
    lang = request.args.get('lang', 'en')
    strings = translations.get(lang, translations['en'])

    if request.method == 'POST':
        action = request.form.get('action')
        username_to_manage = request.form.get('username')

        if not username_to_manage or len(username_to_manage) < 3:
            flash(strings.get('username_too_short', "Username must be at least 3 characters."), "danger")
            return redirect(url_for('manage_users', lang=lang))

        if action == 'add':
            password = request.form.get('password')
            role = request.form.get('role', 'viewer') # Default role for new users
            if not password or len(password) < 6:
                flash(strings.get('password_too_short', "Password must be at least 6 characters."), "danger")
                return redirect(url_for('manage_users', lang=lang))

            if username_to_manage in users:
                flash(strings.get('username_exists', "User already exists."), "danger")
            else:
                if role not in ['admin', 'analyst', 'viewer']:
                    flash(strings.get('invalid_role', "Invalid role specified for new user."), "danger")
                    return redirect(url_for('manage_users', lang=lang))

                users[username_to_manage] = {'password': generate_password_hash(password), 'role': role}
                flash(strings.get('user_added', f"User {username_to_manage} added with role {role}."), "success")
                logger.info(f"Admin {session.get('user')} added new user: {username_to_manage} with role {role}.")

        elif action == 'delete':
            if username_to_manage == 'admin' and username_to_manage == session.get('user'):
                flash(strings.get('cannot_delete_self', "Cannot delete your own admin account."), "danger")
            elif username_to_manage == session.get('user'): # Any user trying to delete themselves
                flash(strings.get('cannot_delete_self', "Cannot delete your own account while logged in."), "danger")
            elif username_to_manage in users:
                del users[username_to_manage]
                flash(strings.get('user_deleted', f"User {username_to_manage} deleted."), "success")
                logger.info(f"Admin {session.get('user')} deleted user: {username_to_manage}.")
            else:
                flash(strings.get('user_not_found', "User not found."), "danger")

        elif action == 'update_role':
            new_role = request.form.get('new_role')
            if username_to_manage in users:
                if username_to_manage == 'admin' and new_role != 'admin':
                    flash(strings.get('cannot_change_admin_role', "Cannot change the role of the primary admin user."), "danger")
                elif new_role not in ['admin', 'analyst', 'viewer']:
                    flash(strings.get('invalid_role', "Invalid role selected."), "danger")
                else:
                    users[username_to_manage]['role'] = new_role
                    flash(strings.get('role_updated', f"Role for {username_to_manage} updated to {new_role}."), "success")
                    logger.info(f"Admin {session.get('user')} updated role for {username_to_manage} to {new_role}.")
            else:
                flash(strings.get('user_not_found', "User not found."), "danger")
    
    # Pass all users to the template, excluding sensitive info like hashed passwords
    users_for_display = {u: {'role': users[u]['role']} for u in users}
    return render_template('users.html', users=users_for_display, lang=lang, strings=strings)

# --- Main execution block ---
if __name__ == '__main__':
    logger.info("Starting Flask web application.")
    app.run(debug=True, host='0.0.0.0', port=5000)
