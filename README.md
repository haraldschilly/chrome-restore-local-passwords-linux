# chrome-restore-local-passwords-linux

Recover the passwords Chrome/Chromium saved **on disk** on Linux, and export them to
**Chrome-importable CSV files — one per profile**.

The classic use case: your old laptop died, you mounted its disk, and you want your saved
logins back. Point this tool at the old `.config` directory, give it the old login password,
and it walks every profile of **Google Chrome**, **Google Chrome Beta**, and **Chromium**,
decrypts each `Login Data` database, and writes a CSV you can import via
`chrome://password-manager/settings` → **Import**.

> ⚠️ This decrypts **your own** passwords from a disk **you control**. Don't use it on data
> that isn't yours.

## Why a dedicated tool?

On Linux, Chrome encrypts saved passwords with OSCrypt. Two schemes show up in `Login Data`:

- **`v10`** — key derived from the hardcoded password `peanuts` (used when the browser ran with
  `--password-store=basic` or had no usable keyring).
- **`v11`** — key derived from a random *"Chrome Safe Storage"* / *"Chromium Safe Storage"*
  secret stored in your **GNOME login keyring** (`~/.local/share/keyrings/login.keyring`), which
  is itself unlocked by your **login password**.

This tool handles both: it decodes the legacy GNOME keyring file offline (given your login
password), extracts the Safe Storage secrets, derives the AES keys, and decrypts every entry.

## Requirements

- Linux with a **GNOME Keyring** (libsecret) — i.e. the `v11` secret lives in a
  `login.keyring` file. (Pure-`v10` data decrypts with no password and no keyring.)
- Google Chrome, Google Chrome Beta, and/or Chromium profiles.
- Nothing to install if you use [`uv`](https://docs.astral.sh/uv/) (below); otherwise Python ≥ 3.9
  and the `cryptography` package.

## Usage with `uvx` (no install)

```bash
# See the options
uvx chrome-restore-local-passwords-linux@latest --help

# List the profiles found on a mounted old disk (no password needed)
uvx chrome-restore-local-passwords-linux@latest \
    --config-dir /run/media/you/OLDDISK/home/you/.config --list

# Decrypt everything and write CSVs (prompts for the OLD login password)
uvx chrome-restore-local-passwords-linux@latest \
    --config-dir /run/media/you/OLDDISK/home/you/.config \
    --out ~/chrome-passwords-export
```

`--config-dir` defaults to `~/.config`, so on your *current* machine you can just run it with no
arguments to export your own profiles. When restoring from another disk, point it at that disk's
`.config`; the matching `login.keyring` is auto-detected next to it (override with `--keyring`).

## Options

| Option | Description |
| --- | --- |
| `--config-dir DIR` | A `.config` directory to read. Default: `~/.config`. |
| `--out DIR` | Output directory for the CSV files. Default: `./chrome-passwords-export`. |
| `--browser NAME` | Restrict to `google-chrome`, `google-chrome-beta`, `google-chrome-unstable`, or `chromium`. Repeatable. Default: all found. |
| `--keyring PATH` | Explicit `login.keyring` path. Default: auto-detected next to `--config-dir`. |
| `--password-stdin` | Read the login password from stdin instead of prompting. |
| `--list` | Only list discovered profiles; don't decrypt. |

The login password can also be supplied via the `CHROME_KEYRING_PASSWORD` environment variable
(handy for scripting; otherwise it's read interactively with `getpass` and never printed).

## Importing the CSVs into Chrome

1. Open a Chrome window **in the profile you want to import into**.
2. Go to `chrome://password-manager/settings`.
3. Click **Import passwords** and pick the CSV for that profile.

Imports land in whichever profile's window you launched the importer from, so match them up.

## Clean up afterwards

The CSVs contain **plaintext passwords** (written `0600`). Delete them securely when done:

```bash
shred -u ~/chrome-passwords-export/*.csv
```

## How it works

1. Parse the legacy GNOME keyring (`GnomeKeyring\n\r\0\n` format): read salt + iteration count,
   derive the AES key from your login password (iterated SHA-256), AES-128-CBC decrypt, and
   verify with the embedded MD5.
2. Extract the `Chrome Safe Storage` / `Chromium Safe Storage` secrets from the decrypted keyring.
3. For each secret, derive the OSCrypt key: `PBKDF2-HMAC-SHA1(secret, "saltysalt", 1, 16)`.
4. For each profile's `Login Data`, decrypt every `v10`/`v11` `password_value`
   (AES-128-CBC, IV = 16 spaces, strip PKCS#7), auto-selecting the secret that validates.
5. Write `name,url,username,password` CSVs in Chrome's import format.

Everything runs **offline**. Your login password is read with `getpass` and is never printed,
logged, or persisted.

## Limitations

- Linux + GNOME Keyring only (no KWallet, no macOS Keychain, no Windows DPAPI).
- Handles OSCrypt `v10`/`v11`. The Windows-only app-bound `v20` scheme does not apply on Linux.
- Reads the legacy single-file keyring format (`login.keyring`). The newer keyring daemon's
  on-disk format is not parsed.

## Development

```bash
uv run chrome_restore_passwords.py --help     # run from source
uv build                                      # build sdist + wheel
```

Releases are published to PyPI automatically by a GitHub Action when a GitHub Release is
published (PyPI Trusted Publishing / OIDC — no API tokens).

## License

[MIT](LICENSE) © Harald Schilly
