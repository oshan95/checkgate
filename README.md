# CheckGate

**Explainable, retrieval-grounded vulnerability detection for CI/CD pipelines, using large language models.**

CheckGate is a GitHub Actions–integrated service that scans pull requests against Java Spring Boot codebases for security vulnerabilities. It uses the Google Gemini API, grounded in current CWE/CVE reference data through retrieval-augmented generation (RAG), to produce explained findings.