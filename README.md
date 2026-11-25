# Storekeeper

A small, careful client for Apple's App Store Connect API, for people and for
coding agents. Python 3.9+, standard library only, macOS.

Its value is the safety layer around the API, not the API coverage:

- **The key stays in the Keychain.** It is read only when a token is signed, then
  handed to macOS's `/usr/bin/openssl` through a pipe (`/dev/fd/N`). It is never
  written to a file, a setting or a log. Apple's own tools, which take only a key
  file, get one for a single command (`with-key`).
- **Dry run by default.** Nothing is sent without `--live` (`Client(live=True)`). A
  dry run reads no key, opens no socket, and returns the planned requests.
- **Requests go to Apple's API host only.** Every path must be an API path
  (`/v<N>/` and plain segments), the URL is checked to be on
  `api.appstoreconnect.apple.com`, and no redirect is followed.
- **Write fences.** Every POST, PATCH and DELETE is checked against an allow-list
  before it is sent. A caller can narrow the list; widening needs an explicit opt-in.
- **Masking of named values.** Personal values the caller names (a review
  contact, a tester's email) become `<private>` in every line and JSON object it
  prints. Values it is not told about are shown as Apple sent them.
- **Agent first.** Every command takes `--json` and prints one JSON object on
  stdout. Exit codes are fixed, every error has a machine code and a one-line
  `fix`, and nothing prompts or waits for input.

It also ships a release guard, `check-icon`, which fails when a built app or its
public store page has no icon.

Storekeeper is not made by, or affiliated with, Apple. App Store Connect is
Apple's service.

## Install

```sh
# Homebrew: this repository is its own tap
brew tap flight-william/storekeeper https://github.com/flight-william/storekeeper
brew install storekeeper

# Or from a checkout, no install at all
python3 -I src/storekeeper/_run.py --version
```

Both run Python with `-I`, so `PYTHONPATH` and the current folder cannot change
what is imported.

## Settings

| Variable | What |
|---|---|
| `ASC_KEY_ID` | the API key's ID (App Store Connect: Users and Access, Integrations): capital letters and digits |
| `ASC_ISSUER` | the issuer ID shown on the same page, e.g. `00000000-0000-0000-0000-000000000000` |
| `STOREKEEPER_KEYCHAIN` | optional: the keychain that holds the key; default `~/Library/Keychains/storekeeper.keychain-db` |
| `STOREKEEPER_SERVICE` | optional: the Keychain item's service; default `storekeeper` |

The key is a generic password in that keychain: service `storekeeper`, account =
the key ID, value = the `.p8` file's base64 body on one line. Team keys only (with
an issuer); individual keys are not supported.

## Keychain setup

Once per key. A keychain of its own, locked by a passphrase you choose, after 15
minutes idle and on sleep:

```sh
kc=~/Library/Keychains/storekeeper.keychain-db
security create-keychain "$kc"                 # asks for the new passphrase
security set-keychain-settings -l -u -t 900 "$kc"
```

Store the key. `printf` is a shell builtin, so the key's body never appears in
any process's arguments; `security -i` reads the command from stdin:

```sh
id=ABCDE12345                                  # your key ID
body=$(grep -v -- '-----' "AuthKey_$id.p8" | tr -d '\n')
printf 'add-generic-password -U -a "%s" -s storekeeper -w "%s" "%s"\n' \
  "$id" "$body" "$kc" | security -i
unset body
storekeeper key check                          # prints "present"
```

Then remove the `.p8` file (keep an offline backup if you need one). Before live
work, unlock the keychain with `security unlock-keychain "$kc"`. Storekeeper never
unlocks it, and it never reads a locked keychain: `security` would open a password
dialog. It asks Security.framework, which shows no UI, and stops with exit 3.

## Dry run and live

```sh
storekeeper api GET /v1/apps --query 'filter[bundleId]=com.example.app'
storekeeper api POST /v1/betaGroups --body group.json --json      # the plan, as JSON
storekeeper api POST /v1/betaGroups --body group.json --live      # sends it
```

A dry run prints each request (method, path, query, body). With `--json` the
plan is in `result.plan`, so it can be shown to whoever decides before `--live`.
A path is `/v<N>/` followed by segments of letters, digits, `_` and `-`; anything
else (`.`, `%`, a space, a host) is refused as `path_refused`, in a dry run too.
A body must be a JSON object.

A live call logs method, path (no query) and HTTP status only. A redirect is
never followed, because the token would go with it. GET, PATCH and the upload PUT
are retried on 429 and 5xx; POST and DELETE only on 429, because a 5xx may follow
a save. Such a failure is exit 4 (`unsure`): read the resource back before you
send it again. A `Retry-After` longer than 60 seconds is cut to 60.

As a library:

```python
import storekeeper

client = storekeeper.Client(live=False)            # a dry run
client.get("/v1/apps", {"filter[bundleId]": "com.example.app"})
client.plan                                        # what it would have sent

live = storekeeper.Client(True, storekeeper.credentials_from_env())
```

## JSON output

With `--json`, every command prints exactly one JSON object on stdout and nothing
else: for `--help` too, for bad input, and for a bug (`internal`, exit 4, with the
exception's type and place only). The text report goes to stderr. stdout is ASCII
(non-ASCII text is `\uXXXX`-escaped), so any locale prints it.

```json
{"schema_version": 1, "command": "key check", "ok": false, "exit": 1,
 "result": {"keychain": "...", "service": "storekeeper", "key_id_set": true,
            "state": "absent", "stand_in": false},
 "error": {"code": "key_absent", "message": "... holds no App Store Connect key ...",
           "fix": "store the key: the README's 'Keychain setup' steps"}}
```

`ok` is `exit == 0`; `error` is `null` when there is none, and may carry `status`
(the HTTP status). `result` per command:

| Command | `result` |
|---|---|
| `--version` | `version` |
| `--help`, `<command> --help` | `help` |
| `key where` | `keychain`, `service` |
| `key check`, `with-key --check` | `keychain`, `service`, `key_id_set`, `state` (`present`, `absent`, `locked`), `stand_in` |
| `key status [keychain]` | `keychain`, `state` (`unlocked`, `locked`, `absent`), `stand_in` |
| `with-key <command>` | `command` (its name), `command_exit` |
| `check-icon <App.app>` | `mode: "app"`, `app`, `assets_car`, `icon_name`, `icon_found` |
| `check-icon --store-page URL` | `mode: "store_page"`, `url`, `share_image`, `placeholder` |
| `api` | `live`, `plan` (list of `method`, `path`, `query`, `body`), and live: `response` |

`stand_in` is true only when a test's fake `security` answered (see Tests).

## Exit codes

| Exit | Meaning | Error codes |
|---|---|---|
| 0 | ok | |
| 1 | a finding or a refusal | `key_absent`, `key_invalid`, `path_refused`, `write_refused`, `api_error`, `icon_missing`, `icon_placeholder`, `command_failed` |
| 2 | usage, or a setting not set | `usage`, `env_missing` |
| 3 | the keychain is locked | `keychain_locked` |
| 4 | cannot tell: stop, do not retry blindly | `cannot_tell`, `no_signer`, `no_response`, `unsure`, `internal` |

The one exception: `with-key <command>` without `--json` exits with the
command's own exit code.

## Write fences

The default fences (`storekeeper.fences.DEFAULT_FENCES`) allow the writes a
release workflow makes. `<id>` is one segment of letters, digits, `_` and `-`;
"at or below" allows more such segments after it (a relationship, for example).
This list is generated by `storekeeper.fences.markdown()`, and a test keeps it
equal to the code:

<!-- fences:start -->
- POST to exactly: `/v1/bundleIdCapabilities`, `/v1/profiles`, `/v2/inAppPurchases`, `/v1/inAppPurchaseLocalizations`, `/v1/gameCenterDetails`, `/v1/gameCenterLeaderboards`, `/v1/gameCenterLeaderboardLocalizations`, `/v1/gameCenterAchievements`, `/v1/gameCenterAchievementLocalizations`, `/v1/betaGroups`, `/v1/appInfoLocalizations`, `/v1/appStoreVersionLocalizations`, `/v1/appScreenshotSets`, `/v1/appScreenshots`, `/v1/appPreviewSets`, `/v1/appPreviews`, `/v1/appStoreReviewDetails`, `/v1/appStoreReviewAttachments`, `/v1/reviewSubmissions`, `/v1/reviewSubmissionItems`, `/v1/gameCenterAppVersions`, `/v1/inAppPurchasePriceSchedules`, `/v1/inAppPurchaseAvailabilities`, `/v1/inAppPurchaseAppStoreReviewScreenshots`, `/v1/betaTesters`, `/v1/accessibilityDeclarations`, `/v1/betaAppReviewSubmissions`, `/v1/betaBuildLocalizations`, `/v1/appCustomProductPages`, `/v1/appCustomProductPageLocalizations`, `/v1/gameCenterAchievementImages`, `/v1/gameCenterAchievementReleases`
- POST a relationship: `/v1/betaGroups/<id>/relationships/betaTesters`, `/v1/betaGroups/<id>/relationships/builds`
- PATCH at or below: `/v1/appInfoLocalizations/<id>`, `/v1/appStoreVersionLocalizations/<id>`, `/v1/appStoreVersions/<id>`, `/v1/appScreenshots/<id>`, `/v1/appScreenshotSets/<id>`, `/v1/appPreviews/<id>`, `/v1/appPreviewSets/<id>`, `/v1/appStoreReviewDetails/<id>`, `/v1/appStoreReviewAttachments/<id>`, `/v1/reviewSubmissions/<id>`
- PATCH one record: `/v1/apps/<id>` (only `contentRightsDeclaration`), `/v1/appInfos/<id>`, `/v1/ageRatingDeclarations/<id>`, `/v1/gameCenterAppVersions/<id>`, `/v1/inAppPurchaseAppStoreReviewScreenshots/<id>`, `/v1/accessibilityDeclarations/<id>` (only `publish`, `supportsAudioDescriptions`, `supportsCaptions`, `supportsDarkInterface`, `supportsDifferentiateWithoutColorAlone`, `supportsLargerText`, `supportsReducedMotion`, `supportsSufficientContrast`, `supportsVoiceControl`, `supportsVoiceover`), `/v1/betaBuildLocalizations/<id>` (only `whatsNew`), `/v1/appCustomProductPageLocalizations/<id>` (only `promotionalText`), `/v1/gameCenterAchievementImages/<id>` (only `uploaded`)
- DELETE one record: `/v1/appScreenshotSets/<id>`, `/v1/appPreviewSets/<id>`
<!-- fences:end -->

A record with an attribute rule takes a body of `{"data": {"attributes": {...}}}`
and nothing else: no relationships, no `included`.

A caller narrows them to what its own steps write:

```python
from storekeeper.fences import DEFAULT_FENCES

fences = DEFAULT_FENCES.narrow(
    post=["/v1/betaGroups"],
    patch=["/v1/appStoreVersionLocalizations/"],
    patch_records=[], delete=[],
)
client = storekeeper.Client(False, fences=fences)
```

`narrow()` refuses anything the current fences do not hold. Widening is a
decision, never a default: `DEFAULT_FENCES.widen(post=[...],
i_accept_wider_writes=True)`. The result is marked `widened`, and
`fences.as_dict()` shows it. The `api` command always uses the defaults.

The fences guard against mistakes in your code and an agent's, not against code
that wants around them: Python cannot stop `dataclasses.replace()` on a `Fences`
or a call to the client's private `_request`.

## Masking

```python
values = storekeeper.personal_env(client, ("REVIEW_EMAIL", "REVIEW_PHONE"))
storekeeper.env_report(values)    # "REVIEW_EMAIL set, REVIEW_PHONE unset"
```

`personal_env` reads the variables at run time and registers their values with
the client; on the command line, `api --private-env NAME` does the same. Every
line and JSON object then shows `<private>` in their place:

- as typed: a name in another order or spacing, or a phone shown with a country
  code the named value lacks, is not found;
- in any letter case;
- as typed, JSON-escaped (also `\uXXXX`), HTML-escaped, and URL-encoded (either hex case);
- a phone (7 or more digits and only phone punctuation) also with its digits
  grouped any other way, and by its last 10 digits;
- a single word only as a whole word (an escape such as `\n` or `%20` just before
  it counts as a boundary), so `Ann` leaves `Annual` alone; a phone's digits only
  where no other digit touches them, so a number inside an id stays; an email or
  a full name wherever it stands.

What it does not do, on purpose:

- It masks named values only. A live answer from Apple (a list of testers, an
  error text) is shown as Apple sent it, apart from the values you named.
- A value shorter than 3 characters is not masked: it would blank ordinary words.
  A two-letter name stays visible.
- A first and last name are masked as the values you name: name both, or the
  full name too.
- `method` and `path` in a plan are never masked, so the plan always shows where
  a request goes (a path cannot hold an email or a name: see the path rule above).

## with-key

Apple's tools (xcodebuild, altool, notarytool) take only a key file:

```sh
storekeeper with-key xcrun altool --list-providers --apiKey "$ASC_KEY_ID" \
  --apiIssuer "$ASC_ISSUER" --p8-file-path @ASC_KEY@
```

It writes `AuthKey_<ID>.p8` into a fresh private folder,
`$TMPDIR/storekeeper-key.<PID>.XXXXXXXX` (mode 700, the file 600). It puts the file's
path where `@ASC_KEY@` stands in the arguments, and deletes the folder when the
command ends, also on INT, TERM, HUP and QUIT. A command that ignores TERM is
killed after 5 seconds. The arguments are substituted, never evaluated. With
`--json` the key is checked first, the command's stdin is closed and its output
goes to stderr.

A hard kill (SIGKILL, which a harness or CI runner sends on a timeout) or a power
loss cannot be caught: the key file stays in `$TMPDIR/storekeeper-key.*` until the
next `with-key` run. That run deletes this user's own such folders that are older
than 6 hours and whose run (the PID in the name) is no longer alive. Look there
after a crash, or delete them yourself.

## check-icon

```sh
storekeeper check-icon build/Export/Example.app        # before upload
storekeeper check-icon --store-page https://apps.apple.com/app/id0000000000
```

The first form fails when the app's `Assets.car` holds no app icon: an icon
shipped only as an `.icns` can leave the store showing Apple's grey placeholder.
The second form, the only command that uses the network apart from `api --live`,
fails when the page's share image is that placeholder (known by its SHA-256 and
size). It fetches only https on `apps.apple.com` and `*.mzstatic.com`, redirects
included.

## Agent skill

`skills/storekeeper/SKILL.md` teaches a coding agent to use Storekeeper safely.
For Claude Code, copy or link it into your skills folder:

```sh
ln -s "$PWD/skills/storekeeper" ~/.claude/skills/storekeeper
```

Other agents read `AGENTS.md`, which points to the same file.

## Limits

- macOS only (the Keychain, Security.framework, `/usr/bin/security`, `/usr/bin/openssl`).
- **Not a sandbox.** Anyone, or any agent, who can run Storekeeper while the
  keychain is unlocked can read the key: `key pem | cat` or
  `with-key cat @ASC_KEY@` prints it. The refusal to print the key to a
  terminal guards against accidents; it is not a boundary. Lock the keychain when
  no live work is planned.
- One request per `api` call; multi-step workflows belong in your own code on
  the library.
- Team API keys only.
- The fences cover the release workflow above. Anything else needs `widen()`.
- `check-icon --store-page` knows one placeholder image: no match means "not the
  known placeholder", so look at the page once.
- A pip install of the package runs without `-I`, so `PYTHONPATH` could change
  what Python imports; Homebrew and the checkout runner do not have that gap.

## Tests

```sh
for t in tests/test_*.py; do python3 -I "$t"; done
```

No test opens a socket or touches a real keychain. Keychains live in a fake
secret store (`testkit/fake_security.py`). The tool lets it stand in for
`security` only when both `SECURITY_BIN` and `STOREKEEPER_TEST_STAND_IN=1` are
set, never for a keychain in your real `~/Library/Keychains`, and it says so
(`stand_in` in the JSON, a line on stderr). To prove the tool against securityd
itself, run the key tests on real throwaway keychains, each one made in a temp
folder and deleted afterwards:

```sh
STOREKEEPER_REAL_KEYCHAIN=1 python3 -I tests/test_key.py
STOREKEEPER_REAL_KEYCHAIN=1 python3 -I tests/test_with_key.py
```

## Licence

Apache-2.0: [LICENSE](LICENSE).
