import streamlit as st
import math
import hashlib
import requests
import string
import time

def calculate_entropy(password):
    """
    Calculate password entropy manually.
    """
    if not password:
        return 0
    
    char_sets = 0
    if any(c.islower() for c in password):
        char_sets += 26
    if any(c.isupper() for c in password):
        char_sets += 26
    if any(c.isdigit() for c in password):
        char_sets += 10
    if any(c in string.punctuation for c in password):
        char_sets += 32
    
    if char_sets == 0:
        return 0
    
    entropy = len(password) * math.log2(char_sets)
    return entropy

def check_pwned_password(password):
    """
    Check if password exists in known data breaches using the Have I Been Pwned API.
    """
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    return True, int(count)
        return False, 0
    except Exception as e:
        st.error(f"Error checking breach: {e}")
        return False, 0

def estimate_crack_time(entropy):
    """
    Estimate time to crack password based on entropy.
    """
    if entropy == 0:
        return "Instantly"
    
    try:
        time_seconds = (2 ** entropy) / (10 ** 11)
    except OverflowError:
        return "More than the age of the universe"
    
    if time_seconds < 60:
        return f"{time_seconds:.2f} seconds"
    elif time_seconds < 3600:
        minutes = time_seconds / 60
        return f"{minutes:.2f} minutes"
    elif time_seconds < 86400:
        hours = time_seconds / 3600
        return f"{hours:.2f} hours"
    elif time_seconds < 31536000:
        days = time_seconds / 86400
        return f"{days:.2f} days"
    else:
        years = time_seconds / 31536000
        return f"{years:,.2f} years"

def get_strength_rating(entropy, is_breached):
    """
    Determine password strength based on entropy.
    """
    if is_breached:
        return "Very Weak", "danger"
    
    if entropy < 28:
        return "Very Weak", "danger"
    elif entropy < 36:
        return "Weak", "warning"
    elif entropy < 60:
        return "Moderate", "info"
    elif entropy < 128:
        return "Strong", "success"
    else:
        return "Very Strong", "success"

### Streamlit App Layout and Logic

st.set_page_config(page_title="Password Strength Checker", layout="centered")

st.title("🛡️ Password Strength Checker")
st.markdown("Enter a password below to check its security.")

# Use a form to group the input and button
with st.form(key='password_form'):
    password = st.text_input("Enter your password:", type="password")
    submit_button = st.form_submit_button(label="Calculate Strength", type="primary")

# Check if the button was clicked
if submit_button:
    if not password:
        st.warning("Please enter a password to get started.")
    else:
        with st.spinner("Analyzing password..."):
            time.sleep(1)
            entropy = calculate_entropy(password)
            is_breached, breach_count = check_pwned_password(password)

        if is_breached:
            st.error(f"⚠️ **WARNING:** This password was found in {breach_count:,} data breaches! **Do NOT use this password.**")
        else:
            st.success("✓ **Not found** in known data breaches.")

        strength, color = get_strength_rating(entropy, is_breached)
        st.markdown("### Security Metrics")
        st.metric(label="Your Password is:", value=f"{strength}")
        
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**Entropy:** {entropy:.2f} bits")
        with col2:
            st.info(f"**Estimated Crack Time:** {estimate_crack_time(entropy)}")

        st.markdown(
            f"""
            <style>
            div[data-testid="stMetric"] {{
                border: 1px solid var(--st-{color});
                background-color: rgba(255, 255, 255, 0.05);
                padding: 1rem;
                border-radius: 0.5rem;
                color: var(--st-{color});
                font-size: 1.5rem;
            }}
            </style>
            """,
            unsafe_allow_html=True
        )
    
else:
    st.info("Please enter a password to get started.")
