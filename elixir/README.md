# root-cert-finder

Script to identify the root certificate issuer for a list of domains. It reads
a list of domain names, one per line, from standard input. For each domain, an
SSL connection is established so the certificate chain returned by the server
can be inspected. Connections are made concurrently to domains.

I wrote this script to identify the impact of Google's [announcement][1] that
Entrust certificates would not be recognized in Chrome after Nov 12, 2024.

[1]: https://security.googleblog.com/2024/06/sustaining-digital-certificate-security.html

## Usage

```console
$ cat - > domains.txt
att.com
bbc.com
amazon.com
google.com
facebook.com
^D
$ elixir root-cert-finder.exs < domains.txt
facebook.com --> DigiCert High Assurance EV Root CA
google.com --> GlobalSign Root CA
amazon.com --> VeriSign Class 3 Public Primary Certification Authority - G5
bbc.com --> GlobalSign Root CA
att.com --> DigiCert Global Root G2

2  GlobalSign Root CA
1  DigiCert Global Root G2
1  DigiCert High Assurance EV Root CA
1  VeriSign Class 3 Public Primary Certification Authority - G5
```
