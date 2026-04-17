import random
import os
from datetime import datetime, timedelta, timezone

random.seed(42)

NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
ATTACK_IPS = ["45.33.32.156", "198.51.100.23", "203.0.113.77", "185.220.101.5"]
NORMAL_PATHS = ["/", "/index.html", "/about", "/contact", "/products", "/login", "/api/v1/users"]
ATTACK_PATHS = [
    "/?id=1' OR '1'='1",
    "/search?q=<script>alert(1)</script>",
    "/../../etc/passwd",
    "/admin/login.php",
    "/.env",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]
ATTACK_AGENTS = ["sqlmap/1.7.8#stable (https://sqlmap.org)", "Nikto/2.1.6"]


def _random_ts(base: datetime, delta_seconds: int = 0) -> str:
    ts = base + timedelta(seconds=delta_seconds)
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


def generate_apache_log(path: str = "sample_logs/sample_apache.log", lines: int = 800):
    base = datetime(2024, 10, 14, 7, 0, 0, tzinfo=timezone.utc)
    out = []

    for i in range(lines):
        ip = random.choice(NORMAL_IPS)
        method = random.choice(["GET", "POST"])
        path_ = random.choice(NORMAL_PATHS)
        status = random.choice([200, 200, 200, 404, 500])
        bytes_ = random.randint(200, 5000)
        ua = random.choice(USER_AGENTS)
        ts = _random_ts(base, i * 12)
        out.append(f'{ip} - - [{ts}] "{method} {path_} HTTP/1.1" {status} {bytes_} "-" "{ua}"')

    scanner = ATTACK_IPS[1]
    for i, p in enumerate(ATTACK_PATHS * 6):
        ts = _random_ts(base, 3600 + i * 2)
        out.append(f'{scanner} - - [{ts}] "GET {p} HTTP/1.1" 404 217 "-" "{ATTACK_AGENTS[1]}"')

    random.shuffle(out)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    return path


if __name__ == "__main__":
    print("Generating sample logs...")
    p = generate_apache_log()
    print(f"Done: {p}")