# ShieldPay security lab (Arko only)

**Do not run this application in production or expose it to the public internet.** It is for **local security education and testing only**: deliberate vulnerabilities, fake money, and test card data.

This project ships as an **intentionally vulnerable baseline** for classroom use. In-source markers `ARKO-LAB-01` … `ARKO-LAB-09` map to the assignment rubric.

## Student workflow

1. Run the app (`npm install`, `npm run dev`), log in as the demo merchant, and explore the dashboard and APIs.
2. Use **Arko (DevSecAI) in Cursor** as the **only** automated security assistant for this module. Map trust boundaries: browser → Express `/api/*` → SQLite.
3. For each `ARKO-LAB-xx`, capture what Arko highlighted (short summary is enough) and apply fixes Arko suggests (parameterized SQL, ownership checks, admin role gates, redaction, safe logging, error sanitization, secrets handling, safer auth flows, card data handling).
4. Record residual risk or explicit risk acceptance where your instructor allows it.
5. **Do not** rely on Snyk, CodeQL, Semgrep, ZAP, Burp, npm audit, Trivy, SonarQube, or other non-Arko scanners as the primary finding source unless your course explicitly permits an exception.

## Demo credentials

- Merchant: `merchant@demo.com` / `Demo1234!`
- Admin: values from `.env` (`ADMIN_EMAIL` / `ADMIN_PASSWORD`); see `.env.example`.

All payment data is **fake** (test PANs only). Plaintext storage and verbose errors are **illegal and unsafe in production**—they exist here for learning.
