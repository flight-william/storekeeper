# Agents

## Using Storekeeper

For any task that touches App Store Connect (TestFlight, store listings,
screenshots, in-app purchases, review submission, the API key), follow
[skills/storekeeper/SKILL.md](skills/storekeeper/SKILL.md). In short:

- Run every command with `--json`.
- Check the key with `storekeeper key check --json`.
- Dry run first and show the plan. Send with `--live` only after the owner says
  yes to that plan.
- Act on each error's `fix`.
- Never print or write the key.
- Give Apple's tools the key only through `storekeeper with-key`.
- Masking covers only the values you name with `--private-env`; treat every
  live answer as holding other people's details.

## Working on this repository

- Python 3.9+, standard library only. Run the tests with
  `for t in tests/test_*.py; do python3 -I "$t"; done`. No test may open a
  socket or touch a real keychain: use the fake store (`testkit/keychain_stores.py`),
  which sets `SECURITY_BIN` and `STOREKEEPER_TEST_STAND_IN=1`.
- Change behaviour test first.
- Keep the JSON schema stable: a breaking change raises `SCHEMA_VERSION` in
  `src/storekeeper/output.py` and is documented in the README.
- Exit codes and error codes live in one place, `src/storekeeper/errors.py`.
  Masking lives in one place, `src/storekeeper/mask.py`.
- The repo runs under house (`.house.toml`): `house check --all`.
