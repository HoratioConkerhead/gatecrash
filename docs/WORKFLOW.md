# Branching Workflow

A lightweight workflow for solo dev with one or more "stable" users.

## Mental model

| Branch | Who lives here | Promise |
|--------|---------------|---------|
| `master` | Stable users' boxes — anyone you don't want to break | "This works." |
| `dev`    | Your test box | "Might be broken. Tomorrow's master." |

Stable users' boxes are set to auto-update from `master`. Your test box is on `dev` (Config → Updates → Switch branch).

---

## One-time setup

```bash
git checkout master
git pull
git checkout -b dev
git push -u origin dev
```

Then on your test box: **Config → Updates → Git branch → switch to `dev`**.

Stable users' boxes stay on `master` — you don't need to do anything to them.

---

## Day-to-day development

You're on `dev` locally:

```bash
git checkout dev
# ...edit, test, etc...
pytest                     # run the test suite before you push
# bump VERSION (e.g. 0.74.0-dev)
git add -A
git commit -m "what you changed"
git push
```

Your test box pulls from `dev`. Stable users still see only `master` and are unaffected.

Every push runs **CI** (pytest + shellcheck) on GitHub — see the **Actions** tab, or the
✓/✗ status mark next to the commit. `pytest` locally is the fast check; CI is the backstop.

---

## Promoting `dev` to `master` (when `dev` is solid)

**First: make sure CI is green on the latest `dev` commit.** Don't promote a red build.

```bash
git checkout master
git pull
git merge dev
# bump VERSION on master, drop the -dev suffix (e.g. 0.74.0)
git add VERSION
git commit -m "Release 0.74.0"
git push
```

Stable users' auto-update picks it up on their next check.

Then re-sync `dev` so it has the merge commit:

```bash
git checkout dev
git merge master
git push
```

---

## Hotfix path (a stable user finds a bug, can't wait for `dev`)

Branch off `master` directly so the fix doesn't carry your in-progress `dev` work with it:

```bash
git checkout master
git pull
# ...fix...
# bump VERSION (patch, e.g. 0.73.1 → 0.73.2)
git add -A
git commit -m "fix: <what>"
git push                         # stable users get it on next check

git checkout dev
git merge master                 # bring the fix back into dev
git push
```

---

## VERSION bumping

The CLAUDE.md rule still holds — bump on every push. Suggested format:

| Branch | Format | Example |
|--------|--------|---------|
| `master` | `MAJOR.MINOR.PATCH` | `0.73.0` |
| `dev`    | `MAJOR.MINOR.PATCH-dev` | `0.74.0-dev` |

That way the UI's version string tells you which branch a box is on at a glance.

### When to bump what

Be **stingy** with minor bumps — otherwise `1.0` arrives before the project is actually ready for it.

| What changed | Bump |
|--------------|------|
| New tab, new core capability, new mode of operation a user would notice | **minor** (`0.x.0`) |
| Tweaks to existing features, polish, perf, refactors | **patch** |
| Bug fixes | **patch** |
| Dev-only tooling (e.g. branch picker, debug logging) | **patch** |
| Breaking changes that require user action | **major** |

A useful test: *"would a stable user, who only cares that their TV exits via the VPN, notice this?"* If no, it's a patch.

### About 1.0

`1.0` is a **promise**, not a counter. SemVer is fine with `0.150.3` — minor numbers can grow without bound, so don't feel forced to ship 1.0 just because the second number is getting big.

Reserve 1.0 for when the project hits a real milestone, e.g.:
- SD card image is shipping and works flash-and-go
- Open security findings are resolved (or won't-fix and documented)
- A handful of external users are running it without issues
- Documentation is good enough for a stranger to install without help

Until then, keep bumping `0.x` and resist the urge.

### Major (`MAJOR.x.x`)

Only when something **breaks compatibility** — config file format changes, an upgrade requires manual steps, or a saved-state file becomes incompatible. Hasn't been needed yet on this project.

---

## Rules of thumb

- **Never force-push `master` or `dev`.** A stable user's update is `git pull` — force-push will desync them.
- **Never commit a feature directly to `master`.** Finish on `dev`, merge over.
- **Don't promote `dev` → `master` with CI red.** Green build first.
- **Hotfixes are the only exception** — they land on `master` first, then merge back to `dev`.
- **Re-sync regularly.** If you've been hacking on `dev` for a week, occasionally `git merge master` into `dev` so the eventual merge isn't a nightmare.
- **Don't forget the VERSION bump.** You (and any stable users) check the UI to know what's deployed.

---

## Quick reference

```bash
# What branch am I on?
git branch --show-current

# What branch is my test box on?
# → Open the web UI, look at Config → Updates → "Current"

# How far ahead is dev compared to master?
git log master..dev --oneline

# How far behind is master compared to dev?
git log dev..master --oneline    # should be empty if dev is up to date

# Did I forget to bump VERSION?
cat VERSION

# Switch test box to a different branch
# → Config → Updates → Git branch → pick branch → Switch

# Switch test box back to master
# → Same place, pick master
```

---

## When to outgrow this

This workflow stops scaling when:

- You have more than one or two users you don't want to break.
- You want to test a release candidate before publishing it.
- You want hotfixes traceable to specific releases.

Next step at that point: tagged releases on `master` (`git tag v0.74.0 && git push --tags`) and a `release` branch that lags `master` by a confidence window. Don't bother until you actually need it.
