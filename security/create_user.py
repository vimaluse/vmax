from getpass import getpass

from security.auth import hash_password


# ============================================================
# CREATE USER
# ============================================================

def main():

    print()
    print("=" * 50)
    print("        CREATE AUTHENTICATED USER")
    print("=" * 50)
    print()

    username = input(
        "Enter username: "
    ).strip().lower()

    if not username:
        print("ERROR: Username cannot be empty.")
        return

    role = input(
        "Enter role (admin/supervisor/user): "
    ).strip().lower()

    allowed_roles = {
        "admin",
        "supervisor",
        "user",
    }

    if role not in allowed_roles:
        print()
        print("ERROR: Invalid role.")
        print("Allowed roles: admin, supervisor, user")
        return

    password = getpass(
        "Enter password: "
    )

    if not password:
        print("ERROR: Password cannot be empty.")
        return

    confirm_password = getpass(
        "Confirm password: "
    )

    if password != confirm_password:
        print()
        print("ERROR: Passwords do not match.")
        return

    try:
        hashed_password = hash_password(password)

    except ValueError as exc:
        print()
        print(f"ERROR: {exc}")
        return

    print()
    print("=" * 50)
    print("             USER CREATED")
    print("=" * 50)

    print(f"Username : {username}")
    print(f"Role     : {role}")
    print("Password : [hidden]")

    print()
    print("Password Hash:")
    print(hashed_password)

    print()
    print("=" * 50)
    print("Add this user to security/auth.py")
    print("=" * 50)
    print()


if __name__ == "__main__":
    main()