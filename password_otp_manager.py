import bcrypt
import pyotp
import re
import matplotlib.pyplot as plt
import logging
import time

# Set up logging
logging.basicConfig(level=logging.INFO)

# Password Hashing and Validation Functions
def hash_password(password: str) -> str:
    try:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        logging.info("Password hashed successfully.")
        return hashed.decode('utf-8')
    except Exception as e:
        logging.error(f"Error hashing password: {e}")
        return None

def check_password_strength(password: str) -> bool:
    if len(password) < 8:
        logging.warning("Password is too short.")
        return False
    if not re.search(r'[A-Za-z]', password):
        logging.warning("Password must contain at least one letter.")
        return False
    if not re.search(r'\d', password):
        logging.warning("Password must contain at least one digit.")
        return False
    logging.info("Password is strong.")
    return True

def verify_password(password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as e:
        logging.error(f"Error verifying password: {e}")
        return False

# OTP Generation and Validation Functions
def generate_otp(secret: str) -> str:
    totp = pyotp.TOTP(secret)
    otp = totp.now()
    logging.info(f"Generated OTP: {otp}")
    return otp

def verify_otp(secret: str, otp: str) -> bool:
    totp = pyotp.TOTP(secret)
    is_valid = totp.verify(otp)
    if is_valid:
        logging.info(f"OTP {otp} is valid.")
    else:
        logging.warning(f"OTP {otp} is invalid.")
    return is_valid

def generate_secret() -> str:
    secret = pyotp.random_base32()
    logging.info(f"Generated secret: {secret}")
    return secret

# Visualization Functions
def visualize_otp_usage(otp_count: list, time_period: list):
    try:
        plt.plot(time_period, otp_count)
        plt.title('OTP Usage Over Time')
        plt.xlabel('Time Period')
        plt.ylabel('OTP Count')
        plt.grid(True)
        plt.show()
        logging.info("OTP usage graph displayed successfully.")
    except Exception as e:
        logging.error(f"Error displaying OTP usage graph: {e}")

def visualize_password_strength(strength_counts: dict):
    try:
        strengths = list(strength_counts.keys())
        counts = list(strength_counts.values())
        plt.bar(strengths, counts)
        plt.title('Password Strength Distribution')
        plt.xlabel('Strength Level')
        plt.ylabel('Count')
        plt.show()
        logging.info("Password strength distribution graph displayed successfully.")
    except Exception as e:
        logging.error(f"Error displaying password strength distribution graph: {e}")

# Function to interact with the user and get input
def user_interaction():
    print("Welcome to the Password & OTP Management System")

    # Ask the user for a password
    password = input("Enter your password: ")
    
    # Check if the password is strong
    if check_password_strength(password):
        hashed_password = hash_password(password)
        print(f"Your hashed password is: {hashed_password}")
        
        # Verify password (this would normally be done with a stored hashed password)
        verify_input = input("Would you like to verify your password (yes/no)? ")
        if verify_input.lower() == "yes":
            entered_password = input("Enter your password again to verify: ")
            if verify_password(entered_password, hashed_password):
                print("Password verification successful!")
            else:
                print("Password verification failed.")
    else:
        print("Password is too weak. Please choose a stronger password.")

    # Ask for OTP generation and verification
    otp_option = input("Do you want to generate and verify OTP? (yes/no): ")
    if otp_option.lower() == "yes":
        secret = generate_secret()
        otp = generate_otp(secret)
        print(f"Generated OTP: {otp}")
        
        entered_otp = input("Enter the OTP to verify: ")
        if verify_otp(secret, entered_otp):
            print("OTP verified successfully!")
        else:
            print("OTP verification failed.")
    
    # Show visualizations
    show_visualizations = input("Do you want to see visualizations for OTP usage and password strength? (yes/no): ")
    if show_visualizations.lower() == "yes":
        otp_count = [1, 2, 3, 4, 5]
        time_period = ["10 AM", "11 AM", "12 PM", "1 PM", "2 PM"]
        visualize_otp_usage(otp_count, time_period)

        strength_counts = {"weak": 5, "medium": 10, "strong": 3}
        visualize_password_strength(strength_counts)

# Usage of the Functions
if __name__ == "__main__":
    user_interaction()
