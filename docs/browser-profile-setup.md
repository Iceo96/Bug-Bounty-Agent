# Authenticated browser profile (persistent Chromium) for the Temu pilot

The browser research/exploration layer authenticates by **reusing a persistent
Chromium profile that you log into once, manually**. The agent only points the
browser at that profile directory — it never reads, copies, uploads, logs, or
persists the profile's contents (cookies, tokens, passwords, storage-state).

## One-time setup

Pick a local directory for the profile (anywhere private on your machine), e.g.
`C:\Users\<you>\temu-profile`. Then:

### 1. Launch the profile once (headed) and log in

```
.venv\Scripts\python.exe -m bbagent browser-login --profile-dir "C:\Users\<you>\temu-profile" --url https://www.temu.com/
```

(Equivalently: `.venv\Scripts\bbagent.exe browser-login --profile-dir "..."`.)

A real Chromium window opens on the Temu home page.

### 2. Log into Temu manually

Sign in with your researcher account in that window, exactly as you normally
would. Complete any verification/CAPTCHA yourself — the agent will not.

### 3. Close the browser

Close the window. Playwright saves the authenticated session **into the profile
directory** you specified. Nothing is printed or copied by the agent.

### 4. Reuse that same profile for the research run

Point the exploration-only research run at the **same** `--profile-dir`:

```
set BBAGENT_BROWSER_LIVE=1
.venv\Scripts\python.exe -m bbagent research programs\temu.yaml --seed https://www.temu.com/ --live --profile-dir "C:\Users\<you>\temu-profile"
```

- `--live` **and** `BBAGENT_BROWSER_LIVE=1` are both required (the deliberate
  two-part live gate). Set the environment variable yourself.
- The browser launches with your persistent, already-authenticated profile.
- Exploration stays within the configured Temu scope, respects the existing
  exploration limits, performs **no** active vulnerability testing, and submits
  nothing.

## Guarantees

- The agent passes only the **path** to Playwright; it never opens, reads, copies,
  uploads, or persists the profile's cookies/tokens/storage-state.
- `launch_persistent_context` is used; the agent never calls `storage_state()` or
  `cookies()`, and captured network headers are redacted before any observation is
  recorded.
- Scope checks and every research safety gate (PolicyGateway, DataScope, RunBudget,
  evidence integrity, human review, no auto-submission, the live gate) are
  unchanged by the profile wiring.
