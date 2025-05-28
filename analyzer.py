from rules import detect_failed_login
from collections import defaultdict
from datetime import datetime, timedelta
import re

LOG_FILE = "logs/test_syslog.log"

def parse_time(line):
    """
    Парсит дату и время из строки лога.
    Пример строки: "May 27 12:00:01 server sshd[12345]: ..."
    """
    pattern = r"^([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2})"
    match = re.match(pattern, line)
    if match:
        time_str = match.group(1)
        # Время без года, подставим текущий год
        dt = datetime.strptime(f"{datetime.now().year} {time_str}", "%Y %b %d %H:%M:%S")
        return dt
    return None

def main():
    failed_login_counts = defaultdict(list)  # IP: [datetime, datetime, ...]

    with open(LOG_FILE, "r") as f:
        for line in f:
            alert = detect_failed_login(line)
            if alert:
                time = parse_time(line)
                ip = re.search(r"from ([\d\.]+)", line).group(1)
                failed_login_counts[ip].append(time)

                # Фильтрация попыток за последние 60 секунд
                window_start = time - timedelta(seconds=60)
                recent_attempts = [t for t in failed_login_counts[ip] if t > window_start]
                failed_login_counts[ip] = recent_attempts

                if len(recent_attempts) >= 5:
                    print(f"ALERT: More than 5 failed login attempts from {ip} within 1 minute!")
                else:
                    print(f"Warning: {alert}")

if __name__ == "__main__":
    main()
