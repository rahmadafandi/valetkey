# valetkey design direction

Applies to every page valetkey serves (sign-in, home, connect, tokens, servers,
activity, consent). The tagline and the theme rule are the owner's words. The
rest was written for the owner at their request and chosen by them on
2026-10-21 ("Keyring"), replacing a first direction whose pages read as a
generic dashboard.

## Tagline

Every Tool. Your Rules.

Owner's words, used verbatim. It goes as the sign-in headline, as the README's
first line under the title, and in the page title where a tagline fits.

## Concept: the keyring

A valet gets a ring with only the keys you put on it. valetkey is that ring:

- **Keys.** Each connected tool is a key hanging on the ring: solid when
  valetkey holds a login for it, pale when it is not on the ring yet. The keys
  hang on cords of different lengths and tilt a little, like real keys. This
  shows real state; it is not decoration.
- **Spare keys.** A personal access token is a smaller ring for a bot: only the
  keys you pick.
- **What was opened.** Activity says what each agent opened and how it went.

The ring and keys appear on the home page only. Other pages use the same
surfaces and type without the picture.

## Personality

Soft and friendly, never cute. A person who does not work in ops should
understand every page: plain words, short sentences, no jargon where a common
word exists.

## Theme

Follows the operating system (`prefers-color-scheme`) with a toggle to switch.
Light and dark must both work fully. Owner's rule.

## Surfaces, not boxes

Areas are told apart by tone, not by outlines: a raised surface on a soft
field. No table rules, no bordered cards, no ruled lines between sections.
Lists are rows of raised surfaces with a small gap between them. A border
appears only on form inputs and on a key that is not on the ring yet.

## Palette

| Token | Light | Dark | Job |
|---|---|---|---|
| `--bg` | `#eef2f5` | `#0d1520` | page |
| `--field` | `#e1e8ee` | `#16212f` | soft areas: nav, sections, inputs at rest |
| `--raised` | `#ffffff` | `#1c2939` | rows and panels on a field |
| `--ink` | `#10233a` | `#e8eef5` | text, solid keys |
| `--soft` | `#34475d` | `#c0ccd9` | secondary text |
| `--muted` | `#4f6074` | `#97a7b8` | hints and times |
| `--accent` | `#ff8a4c` | `#ff9a62` | one action per page, text on it `#1b1206` |
| `--accent-soft` | `#ffe1cf` | `#3a2214` | the spare-keys panel; text `--accent-ink` |

The accent is the single main action of a page (Copy on home, Create token,
Approve these tools). Outcome colours: ok green, refused and error red, dry run
the accent family. Every text pair keeps 4.5:1 and every control edge 3:1.

## Typography

Self-hosted, embedded in the binary, no font CDN. All three are OFL; their
licences sit beside the files in `internal/ui/fonts`.

- **Bricolage Grotesque** 700: headings, key names, the wordmark.
- **Figtree** 400 and 600: everything else.
- **Spline Sans Mono** 400: anything that is code: tool names, arguments,
  tokens, URLs, scope JSON.

## Shape

- Big soft fields: 36 px corners. Rows and panels: 20 px. Inputs and small
  buttons: 12 px.
- Fully round only for the page nav, the address bar on home and the main
  action button. Outcome labels are 10 px, not pills.
- Keys: rounded head (40 px top corners), 18 px bottom corners, a punched hole.
- Shadow only under a solid key, to show it hangs.

## Motion

Hover and focus states only.

## Dials

Dial: ENERGY 3 / RHYTHM 2 / MOTION 1
