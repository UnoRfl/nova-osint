# Using NOVA responsibly

NOVA reads public sources. That is a real limit on what it can do, and it is
not a defence for what you choose to do with it.

## What the tool will not do

These are absent by design, not missing features:

- **No credential handling.** NOVA never looks up, downloads, displays or
  cracks a password from a breach. It will tell you an address appeared in a
  named incident, because that is investigative context. The contents of the
  dump are not.
- **No SMTP probing.** The `email` module never opens a conversation with a
  mail server to test whether a mailbox exists. Everything it reports comes
  from DNS, a public profile API, or arithmetic on the address itself.
- **No messaging-app enumeration.** NOVA prints a WhatsApp or Telegram link for
  you to open. It does not automate "is this number registered", which breaks
  those platforms' terms and mostly gets your own account banned.
- **No content brute-forcing.** The `exposed` module fetches files that are
  *meant* to be public - `robots.txt`, `security.txt`, `sitemap.xml`. It does
  not guess at admin panels, backups or database dumps.
- **No CAPTCHA solving, no scraping behind a login, no authenticated APIs
  belonging to someone else.**
- **No search-engine scraping.** The `dorks` module builds query URLs and hands
  them to you. Automating Google gets you a CAPTCHA within a dozen requests and
  breaches its terms.

## What it does do, and what that costs other people

Every module is rate-limited per host and runs through a shared cache, because
crt.sh, HIBP and the Internet Archive are free services run by people who did
not sign up to host your scan loop. `--delay` raises the gap between requests;
please raise it rather than lower it if you are scanning at volume.

`--passive` is stronger than politeness: it blocks every module that would send
a packet to infrastructure the target controls. Under `--passive` the target
cannot see you at all, only the third parties you queried can. Use it when the
target should not know they were looked at, and when you are not sure you have
standing to touch their systems.

## The part that is on you

"Publicly available" is not the same as "fair to aggregate". Each individual
finding here is already public; the report is not, because collecting scattered
facts into one profile is a different act from reading any one of them. That is
precisely why this class of tool is useful, and precisely why it can cause harm.

Before you run it against a person or an organisation:

- **Have a reason and, where it applies, authorisation.** A scope document, a
  bug-bounty programme, an engagement letter, your own assets, a CTF.
- **Know your jurisdiction.** Automated collection about identifiable people is
  regulated in many places - GDPR in the EU/UK, the Data Privacy Act 2012 in the
  Philippines, CFAA-adjacent law in the US. Aggregation can be the regulated
  act even when each source is open.
- **Keep the output like the sensitive material it is.** `reports/` is
  git-ignored for a reason. Do not commit scan results, and do not publish a
  profile of a private individual.
- **Verify before you act.** Confidence is marked on every finding for a reason.
  `likely` means a heuristic fired. IP geolocation is city-level at best and
  frequently points at a datacentre. A username matching on 40 sites does not
  mean one person owns all 40 accounts - common handles collide constantly.

If you are investigating a private individual who has not consented and you are
not law enforcement acting under proper authority, stop and reconsider. The
tool will let you. That is not the same as it being fine.
