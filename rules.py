import re

def detect_failed_login(line):
    """
    Ищет строки с неудачными попытками входа.
    Возвращает описание тревоги, если обнаружено.
    """
    pattern = r"Failed password for .* from ([\d\.]+)"
    match = re.search(pattern, line)
    if match:
        ip = match.group(1)
        return f"Failed login attempt from IP {ip}"
    return None
