# Security & responsible use

`apirecon` can capture browser traffic and replay modified HTTP requests (including derived ID probes).

- Use it **only** against systems where you have **explicit authorization** for security testing or internal QA.
- **Do not** aim traffic capture or replay at third-party sites, payment processors, healthcare data, or other sensitive platforms without permission and contractual scope.
- Replay mode issues **HTTP requests** that may touch production APIs; combine with **`--scope-file`**, low **`--max-rps`**, and tokens only when your program allows live testing.

Report vulnerabilities in **this tool** via GitHub Issues or private disclosure as you prefer.
