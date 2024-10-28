import streamlit as st
import hashlib
import sqlite3
import os
import pyotp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from google.cloud import storage
from web3 import Web3
import random

# Set up SQLite database
DB_FILE = 'users.db'
# Initialize database connection
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    otp_secret TEXT  DEFAULT ''
)
''')
conn.commit()


OTP_EMAIL_SENDER='ayonsomaddar@gmail.com'
OTP_EMAIL_PASSWORD='uoaf frzy qubb asjd'
smtp_server = 'smtp.gmail.com'
smtp_port = 587


# Hash the password with a salt
def hash_password(password, salt):
    hasher = hashlib.sha256()
    hasher.update(salt.encode() + password.encode())
    return hasher.hexdigest()

# Verify user credentials (ZKP-like)
def verify_zkp(username, password):
    cursor.execute("SELECT password_hash, salt, otp_secret FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user is None:
        return False

    stored_password_hash, stored_salt, otp_secret = user
    provided_password_hash = hash_password(password, stored_salt)
    
    return provided_password_hash == stored_password_hash, otp_secret

# Store a new user (registration)
def store_user(username, password):
    salt = os.urandom(16).hex()  # Generate a random salt
    password_hash = hash_password(password, salt)
    otp_secret = pyotp.random_base32()  # Generate OTP secret
    
    try:
        cursor.execute("INSERT INTO users (username, password_hash, salt, otp_secret) VALUES (?, ?, ?, ?)", (username, password_hash, salt, otp_secret))
        conn.commit()
    except sqlite3.IntegrityError:
        st.error(f"User {username} already exists.")
        return None
    
    return otp_secret


def send_otp(email, otp):
    msg = MIMEMultipart()
    msg['From'] = OTP_EMAIL_SENDER
    msg['To'] = email
    msg['Subject'] = 'Your OTP Code'

    body = f'Your OTP code is {otp}'
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(OTP_EMAIL_SENDER, OTP_EMAIL_PASSWORD)
            server.send_message(msg)
            print('OTP sent successfully!')
    except smtplib.SMTPException as e:
        print(f'Failed to send OTP: {e}')
    except Exception as e:
        print(f'Unexpected error: {e}')
        
def send_passkey(pass_key,email):
    msg = MIMEMultipart()
    msg['From'] = OTP_EMAIL_SENDER
    msg['To'] = email
    msg['Subject'] = 'Your passkey'

    body = f'Your passkey  is {pass_key}'
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(OTP_EMAIL_SENDER, OTP_EMAIL_PASSWORD)
            server.send_message(msg)
            
    except smtplib.SMTPException as e:
        print(f'Failed to send passkey: {e}')
    except Exception as e:
        print(f'Unexpected error: {e}')
    
# Generate OTP
def generate_otp(secret):
    otp = pyotp.TOTP(secret)
    return otp.now()

# Verify OTP
def verify_otp(secret, otp):
    
    return secret==otp

# Generate a simple pass key
def generate_pass_key():
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))

# Set up Google Cloud Storage client
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '/Users/ayonsomaddar/Major Project/GCP/quantum-hash-434506-s4-0cc0e940233d.json'
storage_client = storage.Client()

# Blockchain setup
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))  # Connect to local Ethereum network (e.g., Ganache)
contract_address = '0xF7e168136467023384B3efBa7375c4C915304B25'
contract_abi = [
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": True,
                "internalType": "address",
                "name": "user",
                "type": "address"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "fileName",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            }
        ],
        "name": "DownloadLogged",
        "type": "event"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "fileName",
                "type": "string"
            }
        ],
        "name": "logDownload",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "fileName",
                "type": "string"
            }
        ],
        "name": "logUpload",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": True,
                "internalType": "address",
                "name": "user",
                "type": "address"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "fileName",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "uint256",
                "name": "timestamp",
                "type": "uint256"
            }
        ],
        "name": "UploadLogged",
        "type": "event"
    }
]

contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def log_upload_to_blockchain(user, file_name):
    tx_hash = contract.functions.logUpload(file_name).transact({
        'from': w3.eth.accounts[0]  # Replace with appropriate account
    })
    w3.eth.wait_for_transaction_receipt(tx_hash)
    st.success(f"Upload of {file_name} logged on blockchain!")

def log_download_to_blockchain(user, file_name):
    tx_hash = contract.functions.logDownload(file_name).transact({
        'from': w3.eth.accounts[0]  # Replace with appropriate account
    })
    w3.eth.wait_for_transaction_receipt(tx_hash)
    st.success(f"Download of {file_name} logged on blockchain!")

def upload_to_bucket(blob_name, file_data, bucket_name):
    try:
        bucket = storage_client.get_bucket(bucket_name)
        blob = bucket.blob(blob_name)
        blob.upload_from_string(file_data)  # Directly upload the file without encryption

        log_upload_to_blockchain(st.session_state['username'], blob_name)  # Log the upload

        return True
    except Exception as e:
        st.error(f"Failed to upload {blob_name} to {bucket_name}: {e}")
        return False

def list_files_in_bucket(bucket_name):
    try:
        bucket = storage_client.get_bucket(bucket_name)
        blobs = bucket.list_blobs()
        return [blob.name for blob in blobs]
    except Exception as e:
        st.error(f"Failed to list files in {bucket_name}: {e}")
        return []

def download_from_bucket(blob_name, bucket_name):
    try:
        bucket = storage_client.get_bucket(bucket_name)
        blob = bucket.blob(blob_name)
        file_data = blob.download_as_bytes()  # Directly download the file without decryption

        log_download_to_blockchain(st.session_state['username'], blob_name)  # Log the download

        return file_data
    except Exception as e:
        st.error(f"Failed to download {blob_name} from {bucket_name}: {e}")
        return None


def otp_verification(otp_secret,email):
    st.title("Login Key Verification")

    otp_code = st.text_input("Enter OTP", type="password")
    if st.button("Verify LOGKEY"):
        if verify_otp(otp_secret, otp_code):
            st.success("OTP verified successfully!")

        else:
            st.error("Invalid OTP. Please try again.")


# Streamlit Login Page using ZKP-like Authentication
def login():
    st.title("Login with ZKP-like Authentication")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    email=st.text_input("Email")
    
    
    if st.button("Login"):
        is_valid, otp_secret = verify_zkp(username, password)
        if is_valid:
            st.session_state['otp_secret'] = otp_secret
            otp_verification(otp_secret,email)
            st.session_state['logged_in'] = True
            st.session_state['username'] = username
            pass_key = generate_pass_key()
            send_passkey(pass_key, email)
            st.session_state['pass_key'] = pass_key
        else:
            st.error("Invalid credentials or ZKP failed.")
            
# Streamlit Registration Page
def register():
    st.title("Register")
    username = st.text_input("Choose a username")
    password = st.text_input("Choose a password", type="password")
    email = st.text_input("Enter your email")

    if st.button("Register"):
        otp_secret = store_user(username, password)
        if otp_secret:
            otp = generate_otp(otp_secret)
            send_otp(email, otp)  # Send OTP to user
            st.success(f"User {username} registered successfully! Check your email for the OTP.")

            
# Main Application Page
def app():
    st.title(f"Welcome, {st.session_state['username']}!")

    # File Upload Section
    uploaded_file = st.file_uploader("Choose a file to upload")
    if uploaded_file is not None:
        bucket_name = 'ayon_bucket'
        file_name = uploaded_file.name

        if st.button("Upload"):
            file_data = uploaded_file.getbuffer().tobytes()  # Get file bytes
            success = upload_to_bucket(file_name, file_data, bucket_name)

            if success:
                st.success(f"File {file_name} uploaded successfully to {bucket_name}!")
            else:
                st.error("Failed to upload the file.")

    # List and Download Files Section
    st.subheader("Files in Bucket")
    bucket_name = 'ayon_bucket'
    files = list_files_in_bucket(bucket_name)
    if files:
        selected_file = st.selectbox("Select a file to download", files)
        pass_key = st.text_input("Enter pass key to download the file", type="password")
        
        if st.button("Download"):
            file_content = download_from_bucket(selected_file, bucket_name)
            if file_content:
                # Check pass key
                if pass_key == st.session_state.get('pass_key'):
                    st.download_button(
                        label="Download File",
                        data=file_content,
                        file_name=selected_file
                    )
                else:
                    st.error("Invalid pass key.")

# Run the app
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

if st.session_state['logged_in']:
    app()
else:
    login_option = st.sidebar.radio("Choose an option", ("Login", "Register"))
    if login_option == "Login":
        login()
    else:
        register()
