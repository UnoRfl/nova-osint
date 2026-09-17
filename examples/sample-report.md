# OSINT report: `scanme.nmap.org`

- **Type:** domain
- **Generated:** 2026-09-17 10:31:47 Malay Peninsula Standard Time
- **Modules:** 9  |  **Findings:** 49  |  **Errors:** 1

## Highlights

- **HTTPS** - not available - served over plaintext HTTP
- **security headers missing** - HSTS: browsers may fall back to plaintext, no CSP: XSS has no second line of defence, MIME sniffing is allowed, clickjacking not blocked (unless CSP frame-ancestors), full URLs leak to third parties, no restriction on camera/mic/geolocation APIs
- **SPF** - missing
- **DMARC** - missing

## breaches

| | Field | Value | Source |
|---|---|---|---|
|  | known breaches | none recorded for scanme.nmap.org | hibp |


## dns

| | Field | Value | Source |
|---|---|---|---|
|  | A | 45.33.32.156 | doh |
|  | AAAA | 2600:3c01::f03c:91ff:fe18:bb2f | doh |


## dorks

| | Field | Value | Source |
|---|---|---|---|
|  | subdomains indexed | [site:*.scanme.nmap.org -www](https://www.google.com/search?q=site%3A%2A.scanme.nmap.org%20-www) | dorks |
|  | documents | [site:scanme.nmap.org (filetype:pdf OR filetype:docx OR filetype:xlsx)](https://www.google.com/search?q=site%3Ascanme.nmap.org%20%28filetype%3Apdf%20OR%20filetype%3Adocx%20OR%20filetype%3Axlsx%29) | dorks |
|  | config and backups | [site:scanme.nmap.org (ext:env OR ext:bak OR ext:sql OR ext:log OR ext:conf)](https://www.google.com/search?q=site%3Ascanme.nmap.org%20%28ext%3Aenv%20OR%20ext%3Abak%20OR%20ext%3Asql%20OR%20ext%3Alog%20OR%20ext%3Aconf%29) | dorks |
|  | directory listings | [site:scanme.nmap.org intitle:"index of"](https://www.google.com/search?q=site%3Ascanme.nmap.org%20intitle%3A%22index%20of%22) | dorks |
|  | login portals | [site:scanme.nmap.org (inurl:login OR inurl:signin OR inurl:admin)](https://www.google.com/search?q=site%3Ascanme.nmap.org%20%28inurl%3Alogin%20OR%20inurl%3Asignin%20OR%20inurl%3Aadmin%29) | dorks |
|  | exposed dashboards | [site:scanme.nmap.org (intitle:"dashboard" OR intitle:"phpMyAdmin" OR intitle:"Grafana")](https://www.google.com/search?q=site%3Ascanme.nmap.org%20%28intitle%3A%22dashboard%22%20OR%20intitle%3A%22phpMyAdmin%22%20OR%20intitle%3A%22Grafana%22%29) | dorks |
|  | API docs and keys | [site:scanme.nmap.org (inurl:api OR inurl:swagger OR "api_key" OR "apikey")](https://www.google.com/search?q=site%3Ascanme.nmap.org%20%28inurl%3Aapi%20OR%20inurl%3Aswagger%20OR%20%22api_key%22%20OR%20%22apikey%22%29) | dorks |
|  | staging and dev hosts | [site:scanme.nmap.org (inurl:dev OR inurl:staging OR inurl:test OR inurl:uat)](https://www.google.com/search?q=site%3Ascanme.nmap.org%20%28inurl%3Adev%20OR%20inurl%3Astaging%20OR%20inurl%3Atest%20OR%20inurl%3Auat%29) | dorks |
|  | employees on LinkedIn | [site:linkedin.com/in "scanme.nmap.org"](https://www.google.com/search?q=site%3Alinkedin.com/in%20%22scanme.nmap.org%22) | dorks |
|  | code leaks on GitHub | [site:github.com "scanme.nmap.org"](https://www.google.com/search?q=site%3Agithub.com%20%22scanme.nmap.org%22) | dorks |
|  | pastebin mentions | [site:pastebin.com "scanme.nmap.org"](https://www.google.com/search?q=site%3Apastebin.com%20%22scanme.nmap.org%22) | dorks |
|  | public Trello boards | [site:trello.com "scanme.nmap.org"](https://www.google.com/search?q=site%3Atrello.com%20%22scanme.nmap.org%22) | dorks |
|  | S3 buckets | [(site:s3.amazonaws.com OR site:storage.googleapis.com) "scanme.nmap.org"](https://www.google.com/search?q=%28site%3As3.amazonaws.com%20OR%20site%3Astorage.googleapis.com%29%20%22scanme.nmap.org%22) | dorks |
|  | open Jira / Confluence | [(site:atlassian.net OR inurl:jira) "scanme.nmap.org"](https://www.google.com/search?q=%28site%3Aatlassian.net%20OR%20inurl%3Ajira%29%20%22scanme.nmap.org%22) | dorks |
|  | mentioned in job posts | [("scanme.nmap.org") (site:greenhouse.io OR site:lever.co OR site:workable.com)](https://www.google.com/search?q=%28%22scanme.nmap.org%22%29%20%28site%3Agreenhouse.io%20OR%20site%3Alever.co%20OR%20site%3Aworkable.com%29) | dorks |
|  | github code: hardcoded secrets | ["scanme.nmap.org" (password OR secret OR api_key OR token) language:yaml](https://github.com/search?type=code&q=%22scanme.nmap.org%22%20%28password%20OR%20secret%20OR%20api_key%20OR%20token%29%20language%3Ayaml) | dorks |
|  | github code: environment files | ["scanme.nmap.org" filename:.env](https://github.com/search?type=code&q=%22scanme.nmap.org%22%20filename%3A.env) | dorks |
|  | github code: cloud credentials | ["scanme.nmap.org" (AWS_SECRET_ACCESS_KEY OR aws_access_key_id)](https://github.com/search?type=code&q=%22scanme.nmap.org%22%20%28AWS_SECRET_ACCESS_KEY%20OR%20aws_access_key_id%29) | dorks |
|  | github code: internal hostnames | ["scanme.nmap.org" (internal OR intranet OR vpn)](https://github.com/search?type=code&q=%22scanme.nmap.org%22%20%28internal%20OR%20intranet%20OR%20vpn%29) | dorks |
|  | github code: database strings | ["scanme.nmap.org" (jdbc OR mongodb+srv OR postgres://)](https://github.com/search?type=code&q=%22scanme.nmap.org%22%20%28jdbc%20OR%20mongodb%2Bsrv%20OR%20postgres%3A//%29) | dorks |


## headers

| | Field | Value | Source |
|---|---|---|---|
| !! | HTTPS | not available - served over plaintext HTTP | http |
|  | final URL | http://scanme.nmap.org | http |
|  | status | 200 | http |
|  | page title | Go ahead and ScanMe! | http |
| * | banner: server | Apache/2.4.7 (Ubuntu) | http |
| !! | security headers missing | HSTS: browsers may fall back to plaintext, no CSP: XSS has no second line of defence, MIME sniffing is allowed, clickjacking not blocked (unless CSP frame-ancestors), full URLs leak to third parties, no restriction on camera/mic/geolocation APIs | analysis |


## mailsec

| | Field | Value | Source |
|---|---|---|---|
| * | MX | none - domain cannot receive mail | doh |
| !! | SPF | missing | doh |
| !! | DMARC | missing | doh |


## subdomains

| | Field | Value | Source |
|---|---|---|---|
|  | source: certspotter | 0 name(s) | certspotter |
|  | source: hackertarget | 1 name(s) | hackertarget |
|  | source: rapiddns | 0 name(s) | rapiddns |
|  | subdomains | none found | ct |

> warning: crt.sh unavailable

## wayback

| | Field | Value | Source |
|---|---|---|---|
|  | first capture | [2006-07-01](https://web.archive.org/web/20060701202328/scanme.nmap.org) | wayback |
|  | last capture | [2026-08-26](https://web.archive.org/web/20260826165350/scanme.nmap.org) | wayback |
|  | archived URLs | 83 | wayback |
|  | historic query parameters | C, page, v | wayback |


## whois

| | Field | Value | Source |
|---|---|---|---|
|  | registrable domain | nmap.org | rdap |
|  | domain | nmap.org | rdap |
|  | expires | 2029-01-18 (855 days from now) | rdap |
|  | registered | 1999-01-18 (10103 days ago) | rdap |
|  | last changed | 2026-08-12 (35 days ago) | rdap |
|  | status | client transfer prohibited | rdap |
|  | entity (registrar) | Dynadot Inc | rdap |
|  | nameservers | ns1.linode.com, ns2.linode.com, ns3.linode.com, ns4.linode.com, ns5.linode.com | rdap |
| * | DNSSEC | not signed | rdap |


## Pivots

- `45.33.32.156` (ip) - A record for scanme.nmap.org
- `2600:3c01::f03c:91ff:fe18:bb2f` (ip) - AAAA record for scanme.nmap.org