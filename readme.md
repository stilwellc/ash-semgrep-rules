# Ash Authorization Semgrep Rules

## Overview

This Semgrep ruleset is designed to **detect potential authorization and policy misconfigurations** in [Ash Framework](https://hexdocs.pm/ash/authorization.html) applications.  

It covers **API, resource, policy, runtime, and background job layers**, helping prevent:

- Missing or misconfigured policies  
- Execution without a proper actor context  
- Manual bypasses of Ash authorization  
- Unsafe policy expressions that can disable enforcement  

> These rules are particularly useful for enforcing **secure defaults** in CI/CD pipelines and catching subtle runtime bypasses.

---

## Rules Included

| Rule ID | Description | Layer | Severity |
|---------|-------------|-------|---------|
| `ash-api-missing-authorization` | Detects Ash API modules missing `authorize?: true` or `Ash.Policy.Authorizer` | API | HIGH |
| `ash-resource-missing-policy` | Detects Ash resources without `authorize? true` or `policies do` | Resource | HIGH |
| `ash-policy-unsafe-expression` | Detects unsafe policy expressions (`always()` or trivially true/false) | Policy | MEDIUM |
| `ash-changeset-missing-actor` | Detects changesets or queries executed without a valid `actor:` | Runtime | HIGH |
| `ashoban-job-missing-actor` | Detects AshOban jobs missing an explicit `actor:` | Async / Job | HIGH |
| `ash-identity-user-bypass` | Detects direct access to `identity.user` (or `identity.*`) outside policy context | Runtime | HIGH |
| `ash-manual-authorization-risk` | Detects manual calls to `authorize/2` or `authorize/3` | Runtime | HIGH |

---

## Why These Rules Matter

1. **Resource & API Enforcement**  
   Ensures that all Ash resources and APIs are protected by policies. Missing configuration can result in **silent bypasses of authorization**.

2. **Policy Misconfiguration**  
   Detects trivially true or unsafe policy expressions that may **disable enforcement** and lead to privilege escalation.

3. **Runtime Actor Misuse**  
   Ensures that changesets, queries, and jobs always run with a **valid actor context**, preventing bypass of policy rules.

4. **Manual Authorization / Identity Access**  
   Catches cases where developers manually check `identity.user` or call `authorize/3`, which is **error-prone and risky**.

---
