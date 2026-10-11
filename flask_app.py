from flask import Flask, request
from datetime import datetime

app = Flask(__name__)

def parse_xff(xff_value: str):
    if not xff_value:
        return []
    # X-Forwarded-For can be "ip1, ip2, ip3" (IPs may be IPv4 or IPv6)
    return [ip.strip() for ip in xff_value.split(",") if ip.strip()]

@app.route("/", methods=["GET", "POST"])
def log_ip():
    remote_addr = request.remote_addr  # may be IPv4 or IPv6

    x_forwarded_for_raw = request.headers.get("X-Forwarded-For", "")
    x_real_ip = request.headers.get("X-Real-IP", "")
    via = request.headers.get("Via", "")

    xff_list = parse_xff(x_forwarded_for_raw)
    best_guess_ip = xff_list[0] if xff_list else remote_addr

    # Optional: log whether each value contains ":" (common marker for IPv6),
    # but we still store the raw IPs.
    def is_ipv6(ip: str | None) -> bool:
        return bool(ip) and ":" in ip

    line = (
        f"{datetime.utcnow().isoformat()}Z | "
        f"best_guess={best_guess_ip} (ipv6={is_ipv6(best_guess_ip)}) | "
        f"remote_addr={remote_addr} (ipv6={is_ipv6(remote_addr)}) | "
        f"X-Forwarded-For_raw={x_forwarded_for_raw} | "
        f"X-Forwarded-For_list={xff_list} | "
        f"X-Real-IP={x_real_ip} (ipv6={is_ipv6(x_real_ip)}) | "
        f"Via={via}\n"
    )

    with open("ip_log.txt", "a", encoding="utf-8") as f:
        f.write(line)

    return "Logged\n"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
