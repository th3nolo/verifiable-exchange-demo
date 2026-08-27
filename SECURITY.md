# Security policy

The hosted exchange uses synthetic markets and Base Sepolia. It does not hold
funds or settle trades. A signing or verification bug can still make its public
claims false, and a network or storage bug can still take the service down.

## Report a vulnerability

Do not open a public issue with exploit details. Open the repository's
**Security** tab and choose **Report a vulnerability**. That starts a private
GitHub advisory for this repository without depending on its repository name.

Include the affected commit, a minimal reproduction, the result you expected,
the result you observed, and the security impact. Redact keys, tokens, server
addresses, and account data from logs or screenshots.

The current `main` branch and the deployment at
<https://exchange.th3nolo.com> are supported. Old commits, experimental
branches, local demo data, disposable demo keys, public testnet addresses, and
synthetic orders are outside the reporting scope unless they expose the current
deployment or invalidate a current verification claim.

This project does not offer a vulnerability bounty.

## Browser key handling

The trading page creates a new demo signing key in tab memory. It writes the
raw seed to unencrypted `localStorage` only after the visitor chooses
**remember key**. The page continues to load keys saved by older versions and
offers **forget key** to remove that saved copy.

A remembered key is not protected from a script running on the same origin or
from a person who can read the browser profile. The protocol also has no key
rotation or account recovery. Do not use these demo accounts for funds or as a
wallet.
