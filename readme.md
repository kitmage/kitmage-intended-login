# Kitmage Intended Login

A WordPress plugin that persists and honors a visitor's intended front-end URL across Force Login, WordPress login, FluentAuth, FluentForms registration, and other custom registration flows.

## What it does

- Stores a short-lived `kitmage_intended_path` cookie for logged-out front-end GET requests.
- Keeps redirect destinations on-site and blocks WordPress internals, auth pages, admin AJAX, common asset/document targets, and configured custom exclusions.
- Sends WordPress registration URLs to `/register/` while preserving a safe `redirect_to` value.
- Redirects successful logins to the requested safe destination or stored intended path.
- Provides a `/continue/` helper flow that consumes and clears the intended destination once the user is logged in.
- Bypasses the Force Login plugin for `/register/`, `/continue/`, `/login/`, FluentForms confirmation flows, and configured custom exclusions.
- Adds a Settings → Kitmage Intended Login submenu for partial-match bypass slugs.
- Optionally enforces login at the early `init` hook for administrator-configured URL path prefixes, protecting pages rendered before Force Login's usual hook.
- Adds `[register_button]` and `[logout_link]` shortcodes.

## Installation

1. Copy `kitmage-intended-login.php` into `wp-content/plugins/kitmage-intended-login/kitmage-intended-login.php`.
2. Activate **Kitmage Intended Login** in the WordPress admin Plugins screen.
3. Ensure your site has public pages at `/register/`, `/continue/`, and `/login/`.

## Custom exclusions

Go to **Settings → Kitmage Intended Login** and enter one slug or partial path per line.

Examples:

```text
teams
wc-memberships
member-registration
```

Partial matches are supported. For example, `teams` matches `/my-account/teams/register/` and `/teams-for-memberships/`.

Matched requests bypass Kitmage Intended Login storage and URL rewrites. Matched redirect destinations are also rejected by the safe redirect sanitizer.

## Early login protection (opt-in)

Some plugins render content and exit before Force Login's usual `template_redirect` handler runs. KIL can enforce login at an earlier `init` hook for only the URL paths you choose.

Go to **Settings → Kitmage Intended Login → Early Login Protection** and add one path prefix per line (no leading slash):

```text
contracts
```

This protects `/contracts/` and all child paths, such as `/contracts/example-agreement/`. It does **not** protect `/other-contracts/`. The setting is empty by default, so there is no behavior change until you configure it.

- Logged-out GET requests are redirected to login, with KIL preserving the requested destination for after login.
- Logged-out non-GET/HEAD requests to protected paths are rejected with HTTP 403 instead of being processed.
- Logged-in visitors can continue; this checks **authentication**, not document-specific roles or signer identity.
- The **existing Bypass slugs** field also makes matching protected paths public. For a single public document, use a distinctive document slug rather than a broad word.
- Force Login continues to handle the rest of the site; this feature is a targeted supplement, not a replacement.

Example: with `contracts` protected, adding `public-consent-example` to **Bypass slugs** exempts `/contracts/public-consent-example/` from early protection and Force Login.

**Security note:** Bypass slugs use partial matching across the full URL path. Broad entries such as `login` or `account` can unintentionally match unrelated protected document names. Review exemptions carefully.

For staging verification, remove or disable any temporary PHP snippet that duplicates early contract protection before testing this feature. Confirm a logged-out contract is redirected, an allowed logged-in account can open it, and a deliberately exempted contract is public. Purge/exclude cached copies of protected pages as needed.

## Shortcodes

### `[register_button]`

Outputs a registration link.

Optional attributes:

- `text` — link text. Default: `Register`.
- `class` — CSS class. Default: `register-button`.
- `url` — link target. Default: `/register/`.

### `[logout_link]`

Outputs `Logout: {display_name}` for logged-in users and nothing for anonymous visitors.
