"""Мини-DAST: динамические проверки запущенного API (аналог правил ZAP).

Использование: python dast_scan.py http://127.0.0.1:5000 [report.json]
Код выхода 1, если найдена хотя бы одна уязвимость High/Medium.
"""
import json
import sys
import uuid

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5000"
OUT = sys.argv[2] if len(sys.argv) > 2 else "dast_report.json"
U = BASE + "/api/users"
findings, passed = [], []


def check(cid, owasp, risk, title, ok, evidence=""):
    (passed if ok else findings).append(
        {"id": cid, "owasp": owasp, "risk": risk, "title": title, "evidence": evidence[:300]})


tag = uuid.uuid4().hex[:6]
for n in ("alice", "bob"):
    requests.post(U, json={"name": f"{n}{tag}", "email": f"{n}{tag}@test.com"}, timeout=5)
total = len(requests.get(U, timeout=5).json())

# 1. SQL Injection в параметре поиска
r = requests.get(U, params={"name": "' OR '1'='1"}, timeout=5)
leaked = r.status_code == 200 and len(r.json()) == total and total > 0
check("D-01", "A03 Injection", "High", "SQL Injection в GET /api/users?name",
      not leaked and r.status_code != 500, f"HTTP {r.status_code}, записей: {len(r.json()) if r.ok else '-'} из {total}")

# 2. SQL-ошибка и раскрытие запроса
r = requests.get(U, params={"name": "'"}, timeout=5)
check("D-02", "A05 Misconfiguration", "Medium", "Раскрытие SQL-ошибки/запроса в ответе",
      r.status_code != 500 and "SELECT" not in r.text, f"HTTP {r.status_code}: {r.text[:150]}")

# 3. Stored XSS
r = requests.post(U, json={"name": "<script>alert(1)</script>", "email": f"x{tag}@test.com"}, timeout=5)
check("D-03", "A03 Injection (XSS)", "Medium", "Сохранение XSS-полезной нагрузки",
      r.status_code == 400, f"HTTP {r.status_code}")

# 4. Удаление без аутентификации
victim = requests.post(U, json={"name": f"victim{tag}", "email": f"v{tag}@test.com"}, timeout=5)
vid = victim.json().get("id") if victim.status_code == 201 else 1
r = requests.delete(f"{U}/{vid}", timeout=5)
check("D-04", "A01 Broken Access Control", "High", "DELETE /api/users/<id> без аутентификации",
      r.status_code in (401, 403), f"HTTP {r.status_code}")

# 5. Защитные заголовки
r = requests.get(U, timeout=5)
for h in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"):
    check("D-05", "A05 Misconfiguration", "Low", f"Отсутствует заголовок {h}", h in r.headers)

# 6. Отладчик Werkzeug / раскрытие сервера
r = requests.get(BASE + "/console", timeout=5)
check("D-06", "A05 Misconfiguration", "High", "Доступна отладочная консоль Werkzeug",
      "Werkzeug" not in r.text or r.status_code == 404, f"HTTP {r.status_code}")

report = {"target": BASE, "findings": findings, "passed": passed}
json.dump(report, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(f"DAST {BASE}: проверок {len(findings) + len(passed)}, уязвимостей {len(findings)}")
for f in findings:
    print(f"  [{f['risk']}] {f['id']} {f['owasp']}: {f['title']} ({f['evidence']})")
sys.exit(1 if any(f["risk"] in ("High", "Medium") for f in findings) else 0)
