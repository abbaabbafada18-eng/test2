# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-08-24

### Changed

- The program now looks for its data instead of assuming it is underfoot.

  Until now everything — vault, settings, results, logs — lived in whatever
  directory the program was started from. That is the program's own folder when
  it is double-clicked on Windows and `/var/lib/minter` for the Linux service,
  right in both cases and wrong everywhere else. Unzipping an update somewhere
  new opened an empty program while the wallets sat in the old folder, and an
  app launched from macOS Finder would try to create `results/` at the root of
  the disk.

  Nothing is moved or copied — a vault is the one file where a stray second copy
  is worse than any inconvenience, and an interrupted move is worse still.
  Instead the location is resolved once at startup, in order: `MINTER_DATA_DIR`
  when it is set; the working directory if the vault is already there; the
  executable's own folder if it is there; the note the program left itself last
  time, if that folder still holds data; and only then a per-user directory of
  the platform's own.

  **Nothing changes for an existing install.** Windows operators keep their data
  in the program folder, and the Linux service keeps `/var/lib/minter` — both
  are caught by the second rule, and the systemd unit now says so outright
  rather than relying on the working directory.

  The note is what makes an update unzipped into a new folder open with the
  wallets already there, which was the trap this began with. Eight tests cover
  the order, including the case where a second portable copy with its own vault
  must stay its own install rather than adopt the first one's data.

- Settings now name the data folder. Finding it was previously a matter of
  guessing, and guessing wrong is what "my wallets are gone" usually turns out
  to be.

## [1.0.2] - 2026-08-24

### Added

- Disperse can fund only the wallets that actually hold the whitelist. Which
  wallets are on a list is knowledge the WL check already has, and picking them
  by hand out of a numbered column is where it goes wrong: the eligible ones are
  1, 6, 12, 34, 53 — not 1 through 5. The saved check now drives the selection,
  and eligible rows carry a WL tag so the choice is visible rather than implied.

### Fixed

- The disperse cost line no longer prices every transfer at Ethereum mainnet.
  It used a fixed 21 000 gas at 30 gwei, which on the L2s these runs actually
  use is roughly a thousand times too much — enough to paint a well-funded
  wallet as short of funds and stop a run that would have gone through. The
  chain is asked instead, once per chain and cached, using the same gas floor
  the engine applies and including the OP chains' separate L1 data fee. When the
  RPC cannot be reached the old figure stands in, because a summary line with no
  number at all breaks the balance check outright.

- The update banner told Linux operators to unzip over their folder. There is no
  such folder on a server install: the binary lives in `/opt/minter` and the data
  in `/var/lib/minter`, and updating means re-running the installer. The banner
  now asks the running build which system it is on — the page could only have
  guessed — and says the right one. The published release notes carry both paths
  under separate headings.

## [1.0.1] - 2026-08-24

### Added

- The countdown now fires by true time rather than by this machine's clock.

  A run aims at a wall-clock instant, so a computer whose clock is a second slow
  fires a second late - and its own log still shows a countdown reaching zero
  exactly on the mark, which is why the fault is invisible from inside. This is
  what was behind runs that arrived about a second late with nothing in the log
  to explain it.

  Before the countdown starts, three public time servers are asked at once and
  the reply that travelled fastest is believed; every later decision about when
  to fire reads the corrected clock, in both the OpenSea and the raw path. One
  line goes into the operator log saying what was found, so a wrong clock is
  visible rather than silent.

  It cannot itself make a run late. The check is skipped when the fire is less
  than five seconds away, the whole query is capped at four seconds, and a
  network that blocks NTP simply leaves the machine's own clock in use with the
  log saying so - as does a failed check after a good one, which keeps the
  correction it already had. A reading further out than an hour is reported but
  not applied: NTP answers in UTC, so a timezone cannot produce one, and
  silently moving a countdown by an hour is worse than leaving it alone.

- Raw mint can knock before the gate opens, with a new "Push early, ms" box.

  A mint succeeds in the first block whose timestamp reaches the start time, so
  a transaction that leaves at T0 has already lost the flight time. With a lead
  set, transactions go out early and repeat, each carrying the condition that it
  must not be included before the start time. Early attempts are refused by the
  node itself: no gas, no nonce, no revert. The attempt that is accepted is the
  mint.

  Wallets are spread across the interval rather than stacked on one tick, so a
  run of fifty does not queue behind itself at the node, and the loop keeps
  knocking for a short while past the target, so a clock running fast cannot
  fire a single volley into a mint that has not opened yet.

  The box next to it, **Measure**, fills the number in from a real measurement:
  round trips to the chain's RPC for the flight, and the time servers for the
  clock. Leaving the box at 0 keeps the previous behaviour exactly.

- Connections are opened before they are needed, not at T0.

  Authentication talks to `opensea.io` while the calldata query talks to
  `gql.opensea.io`, so a freshly authenticated session had no connection to the
  host that actually matters and paid DNS, TCP, TLS and HTTP/2 setup at the one
  instant where it cannot be afforded - through a proxy, a few hundred
  milliseconds per wallet. The connection is now opened during preparation,
  using the CORS preflight a browser sends before the same POST, so it costs
  nothing against the request budget.

- Run metrics record what the run actually did: how long authentication took,
  how long calldata took per wallet including any re-auth, and when each
  transaction was acknowledged and confirmed.

- Ink (chain 57073) joins the network list, across raw mint, disperse, sweep and
  the explorer links. It is an OP-stack chain, so it inherits the elevated gas
  floor and the L1 data fee the other Superchain networks already use.

### Fixed

- The dismiss button on the update banner showed a stray character instead of a
  cross: the multiplication sign had been saved in a single-byte encoding inside
  a UTF-8 page.

- Release notes now say how to update without appearing to lose everything.
  Wallets and settings live in the folder the program runs from, so unzipping a
  new version "anywhere" - which is what the notes suggested - produced a
  second, empty install while the keys stayed behind in the old folder. The
  notes now say to unzip over the existing folder, and explain that the archive
  holds only the program and its documentation. The update banner repeats it in
  one line, so it is read at the moment it matters.

- OpenSea logins were never cached, so every run paid a full sign-in for every
  wallet. OpenSea moved the credential from the response body to a
  `Set-Cookie` header; the code still read the body and got an empty string,
  and the cache refuses to store an empty credential - so `auth_cache.bin` was
  never written and "Warm auth" bought nothing. The token is now read from
  either place. It lives around 84 hours, which turns sign-in from a cost paid
  every run into one paid every few days.

- Authentication no longer ignores how many proxies are configured. The old
  ceiling of six concurrent logins meant a fifty-proxy setup ran at the speed
  of a six-proxy one - about 13s of sign-in for 100 wallets instead of about
  2s. Concurrency now scales with the pool, roughly one login in flight per
  exit IP, which is the ratio measured to complete without failures, and stays
  capped so a very large list cannot open an unbounded burst. A single shared
  IP is still held at two.

- A countdown slice can no longer be scheduled past the fire time. The ladder's
  steps already prevented it, but nothing said so; now the rule is stated in
  the code and held by a test, so changing the steps cannot quietly reintroduce
  an overshoot.

- Operator logs go to stderr. They are progress notes for a human, and stdout
  belongs to whatever a caller is emitting there - a single stray log line makes
  a JSON document unparseable at its first byte.

## [0.2.2] - 2026-08-15

### Fixed

- Burner generation no longer aborts when one backup folder is refused.
  The plaintext recovery file — written before the encrypted vault, so a
  failed vault rewrite is always recoverable — went to `./imports`, resolved
  against the *working directory*, which on Windows is whatever launched the
  program rather than where the program lives. Three ordinary ways to hit it:
  a shortcut whose working directory is `C:\Windows\System32`; running from a
  still-zipped folder, which Explorer extracts read-only; and Controlled
  Folder Access, which refuses folder creation to unsigned programs in
  Downloads, Documents and the Desktop while still permitting the vault to be
  read — which is why the vault opens and only the backup fails.

  There is now a list of candidate directories and generation moves on when
  one cannot be created or written. The order keeps the existing location
  first, so a setup whose working directory already is the vault's directory
  — the Linux service, and double-clicking the executable in its own folder —
  writes exactly where it always has; the fallbacks (beside the executable,
  then the per-user data directory) engage only after a refusal. The path
  actually used is reported back. When every candidate is refused, the error
  names each one with its reason instead of reporting a single path with none,
  and keys are still never committed to the vault without a backup on disk.

## [0.2.1] - 2026-08-14

### Fixed

- Whitelist mints no longer starve themselves of OpenSea's request budget.
  Measured against the live endpoint: calldata is issued only once a stage is
  open — asking earlier returns `DropNotMintingError`, and that was on a public
  sale the wallet was eligible for, so it is timing alone. The budget is five
  mint-action requests per exit IP, refilling roughly one every four seconds,
  and a *refused* request costs a token exactly like a successful one. The
  pre-fetch loop retried every 500 ms through its whole window — about ten
  doomed requests per wallet in the five seconds before open — so wallets
  reached the fire with `x-ratelimit-remaining: 0` and only those that had
  refilled a token could mint. The pre-fetch for stages that are not open is
  removed rather than tuned; local `mintPublic` calldata is unaffected, being
  built offline at no request cost.
- The wait OpenSea asks for is honoured instead of discarded. `retry-after`
  arrives as fractional seconds (`2.5`) and, on the mint-action query, inside
  an HTTP 200 GraphQL error rather than a 429 header. It was parsed as an
  integer, failed, and was reported as "no wait"; the worker then slept a flat
  100 ms three times and gave up — 300 ms against a server asking for 2.5 s.
  Server-requested waits now survive as milliseconds and draw on their own
  budget, so honouring one no longer consumes the three attempts a genuine
  error gets.
- Wallets that reach T0 unarmed are spaced only against others sharing their
  exit IP, since the budget is per IP. A run now warns when more than five
  wallets share one proxy — the case where the surplus genuinely has to wait.
- Pre-fetch failures report why they failed instead of being swallowed.

## [0.2.0] - 2026-08-14

### Added

- Prebuilt releases for both audiences: a Windows zip to run locally and a
  Linux tarball consumed by the VPS installer. Neither needs a Rust toolchain.
- `deploy/linux/install.sh` — one-command install on a headless server.
  Detects apt/dnf/pacman (and derivatives via `ID_LIKE`), enforces the glibc
  and webkit2gtk 4.1 floors before touching anything, verifies the download
  against its published SHA256, and asks the loader which libraries are
  actually missing rather than trusting a hardcoded package list.
- [minter-connect](https://github.com/MaxBetov-pdd/minter-connect) — a Windows
  script that sets up the SSH key, opens the tunnel and launches the GUI.
- RPC transparency: the resolved endpoint order with per-node ping now reaches
  the mint log, and every broadcast names the endpoint that accepted it. Both
  were already computed and then discarded behind `QUIET=1`.
- Per-endpoint ping on the RPCs page, tagged by origin, so a paid provider is
  distinguishable from the public fallback appended to every chain.
- WL auto-load: the task modal reads back saved eligibility results and
  pre-selects the wallets eligible for the phase the task targets.
- Free-form wallet groups, replacing the fixed A/B/C set.

### Fixed

- A failed broadcast is no longer reported as a hard failure. Timeouts and lost
  responses are checked against the chain, the signed hash is kept, and a run
  ends with a reconciliation pass — a mint that landed can no longer be
  recorded as a loss with nothing to look up.
- A receipt lookup that errors is no longer treated as proof the transaction is
  absent, which could make a retry broadcast a second mint.
- Stop now interrupts queued OpenSea authentication instead of waiting for the
  whole queue to drain.
- The pre-auth OpenSea request goes through the wallet's proxy instead of
  leaving from the machine's own IP.
- Tuple and struct call parameters are no longer split on plain commas.

### Changed

- Cargo package metadata (license, repository, authors) on core and desktop
- SECURITY.md with concrete reporting channels
- README polished for public announcement
- Public-launch hygiene: CONTRIBUTING, Code of Conduct, issue/PR templates

## [0.1.0] - 2026-07-24

### Added

- **minter-core** — shared mint / vault / RPC engine (OpenSea SeaDrop + raw sniper)
- **minter-desktop** — Tauri 2 Windows GUI (tasks, Mission Control, wallets, proxies, raw mint)
- Encrypted vault (AES-256-GCM, PBKDF2 600k, Zeroizing)
- LIVE confirm gate, idle lock, dry-run defaults
- Multi-wallet sticky proxies (OpenSea auth path)
- Private Alchemy multi-chain RPC (user key); hedged reads / fan-out
- Results export (JSON/CSV), run history, full mint logs
- Dual license: MIT OR Apache-2.0
- CI: rustfmt, clippy `-D warnings`, `minter-core` tests

### Security

- Tauri CSP (non-null)
- Session / vault Debug redaction
- Wave A–D hardening (LIVE gate, fee caps, zero-address rejects, OpenSea value checks, etc.)

[Unreleased]: https://github.com/MaxBetov-pdd/Minter-rs-v2/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/MaxBetov-pdd/Minter-rs-v2/releases/tag/v1.1.0
[1.0.2]: https://github.com/MaxBetov-pdd/Minter-rs-v2/releases/tag/v1.0.2
[1.0.1]: https://github.com/MaxBetov-pdd/Minter-rs-v2/releases/tag/v1.0.1
[0.2.2]: https://github.com/MaxBetov-pdd/Minter-rs-v2/releases/tag/v0.2.2
[0.2.1]: https://github.com/MaxBetov-pdd/Minter-rs-v2/releases/tag/v0.2.1
[0.2.0]: https://github.com/MaxBetov-pdd/Minter-rs-v2/releases/tag/v0.2.0
[0.1.0]: https://github.com/MaxBetov-pdd/Minter-rs-v2/releases/tag/v0.1.0
