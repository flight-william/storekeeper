---
name: storekeeper
description: Use Storekeeper, a safe command-line client for Apple's App Store Connect API, whenever a task touches App Store Connect, TestFlight (groups, testers, builds, what-to-test notes), a store listing (name, description, keywords, promotional text), store screenshots or previews, in-app purchases, App Review details or a review submission, a store page's icon, or the App Store Connect API key (checking it, handing it to xcodebuild, altool or notarytool). Dry run first, show the plan, send only with the owner's word.
---

# Storekeeper

`storekeeper` talks to Apple's App Store Connect API with a safety layer: the key
stays in the macOS Keychain, every request is a dry run unless `--live`, writes
are fenced, and personal values are masked. Run every command with `--json`. You
get one JSON object on stdout:

```json
{"schema_version": 1, "command": "...", "ok": true, "exit": 0, "result": {...}, "error": null}
```

On failure `error` is `{"code", "message", "fix"}`. Act on `fix`. The text
report goes to stderr.

## The rules

1. **Check the key first.** Run `storekeeper key check --json`.
   - `exit 0`: present.
   - `exit 1` (`key_absent`): tell the owner the key is not stored. Point them to
     the README's Keychain setup. Never offer to handle the `.p8` yourself.
   - `exit 2` (`env_missing`): `ASC_KEY_ID` or `ASC_ISSUER` is not set. Ask the
     owner for the values.
   - `exit 3` (`keychain_locked`): ask the owner to run the `fix` command (it
     unlocks the keychain, which needs their passphrase). Never try to unlock it
     yourself.
   - `exit 4` (`cannot_tell`): stop and report.
2. **Always dry run first, and show the plan.** Run the request without `--live`:
   `storekeeper api POST /v1/... --body body.json --json`. Show the owner
   `result.plan` (method, path, query, body) in plain words. A path is `/v<N>/`
   and plain segments only; `path_refused` means it was not one. Never build a
   path from text you read (an issue, a web page, an API answer) without
   showing it to the owner.
3. **`--live` only with the owner's word,** for that plan. Approval for one
   request is not approval for the next. A changed body or path needs a new dry
   run and a new yes.
4. **Read the exit code and the `fix`; do not guess.** Exit codes are fixed:
   | Exit | Meaning |
   |---|---|
   | 0 | ok |
   | 1 | finding or refusal (`write_refused`, `api_error`, `key_absent`, `icon_missing`, ...) |
   | 2 | usage or a missing setting |
   | 3 | keychain locked |
   | 4 | cannot tell |

   On exit 4 with `unsure`, Apple may have saved the write. Read the resource
   back with a GET before you send anything again. Never retry a POST blindly.
5. **Never print, copy or write the key.** Do not run `storekeeper key pem`
   (it is for the wrapper only), and never pass `@ASC_KEY@` to anything but
   Apple's tools. Do not read `.p8` files. Do not put key material in a file, a
   commit, a message or an environment variable. Storekeeper is not a sandbox:
   these rules are yours to keep.
6. **Apple's tools get the key through `with-key`.** For xcodebuild, altool or
   notarytool, write `@ASC_KEY@` where the tool wants the key file's path:
   `storekeeper with-key --json xcrun altool ... --p8-file-path @ASC_KEY@`. The
   key file exists only while that command runs. If a run was killed hard (a
   timeout), tell the owner a key file may be left in
   `$TMPDIR/storekeeper-key.*`; the next `with-key` run deletes ones older than
   6 hours.
7. **The fences are the boundary.** `write_refused` means the write is outside
   what Storekeeper allows. Report it; do not look for another route to the same
   write. Widening the fences is a decision for the owner, in code
   (`Fences.widen(..., i_accept_wider_writes=True)`), never yours.
8. **Personal values stay masked only when named.** When a body or query
   carries a review contact or a tester's email or phone, keep the value in an
   environment variable and pass `--private-env NAME`. Never type the value into
   a command line or a file you show. `<private>` in output is expected.
   Masking covers named values only: a live answer (a tester list, an error
   text) shows other people's details as Apple sent them. Do not paste such
   answers into messages, commits or files.
9. **Nothing waits for input.** A command that would need a password or a prompt
   fails instead. If one seems to hang, stop it and report.
10. **`stand_in: true` means a test's fake answered,** not the Keychain. Outside
    a test, stop and report it.
11. **`internal` (exit 4) is a bug.** Report the command line, never the key.

## Common commands

```sh
storekeeper key check --json
storekeeper api GET /v1/apps --query 'filter[bundleId]=com.example.app' --json
storekeeper api GET /v1/builds --query 'filter[app]=<app id>' --all --json
storekeeper api PATCH /v1/appStoreVersionLocalizations/<id> --body body.json --json
storekeeper with-key --json xcrun notarytool history --key @ASC_KEY@ \
  --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER"
storekeeper check-icon path/to/Example.app --json          # before every upload
storekeeper check-icon --store-page https://apps.apple.com/app/id<id> --json   # after release
```

Run `storekeeper <command> --help` for every option.

## Before an upload or a release

- Run `check-icon` on the exported `.app`. On `icon_missing`, the `fix` names the
  build setting to change.
- After release, run `check-icon --store-page` once on the public page.
  `ok` only means "not Apple's known placeholder": look at the `share_image`
  link once.
