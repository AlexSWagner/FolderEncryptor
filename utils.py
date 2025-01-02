def validate_passwords(password, confirm_password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if password != confirm_password:
        return False, "Passwords do not match."
    return True, ""
