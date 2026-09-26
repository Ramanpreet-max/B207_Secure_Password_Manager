import secrets
import string


def generate_password(
    length=16,
    use_uppercase=True,
    use_lowercase=True,
    use_numbers=True,
    use_symbols=True
):

    characters = ""

    if use_uppercase:
        characters += string.ascii_uppercase

    if use_lowercase:
        characters += string.ascii_lowercase

    if use_numbers:
        characters += string.digits

    if use_symbols:
        characters += "!@#$%^&*()-_=+"

    if not characters:
        raise ValueError("At least one character type must be selected.")

    if length < 8 or length > 128:
        raise ValueError("Password length must be between 8 and 128.")

    return "".join(
        secrets.choice(characters)
        for _ in range(length)
    )