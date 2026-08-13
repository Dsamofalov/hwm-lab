# hwm-lab

Public trusted evidence/lab policy repository for the HeroesWM autonomous development infrastructure.

## Trust boundary

- Repository visibility and runner hardware ownership do not establish trust. Trusted T1 execution is defined by protected workflow code, protected `main`, exact trusted SHA, actor/event policy, and narrowly scoped credentials.
- PR CI uses ephemeral GitHub-hosted runners with `contents: read`, no secrets, and no `pull_request_target` execution of PR code.
- Reproducible trusted post-merge jobs may also use GitHub-hosted runners when all required inputs are GitHub data or external immutable inputs safe for that workflow.
- Unmerged product candidate code never receives local account/browser credentials and never runs in a trusted persistent environment containing such state.
- This repository currently has no raw corpus, browser profile, account state, cookies, credentials, or local-only evidence access. Any local executor is deferred until I11/I12 and only if a concrete capability requires local-only corpus, persistent browser/account state, closed-network access, or a continuous process.
- If a local executor is later required, prefer a typed service/poller with an allowlisted operation enum over a universal self-hosted runner capable of arbitrary shell execution.

## Public-data boundary

Everything committed here or emitted to public Issues, PRs, Actions logs, or artifacts must be safe for full public disclosure. Do not store tokens, cookies, browser profiles, account credentials, private keys, session data, personal data, or sensitive raw evidence. Standard Git author/committer attribution metadata is expected to be public and is permitted; the personal-data prohibition applies to repository files and other public operational/generated surfaces. Raw corpus is published only after a separate safety determination; otherwise it remains an external/local immutable input.

I01 creates structure and policy only. It does not implement workers, a job bus, Hyper-V pools, product-candidate execution, corpus storage, local account/browser access, or live validation.
