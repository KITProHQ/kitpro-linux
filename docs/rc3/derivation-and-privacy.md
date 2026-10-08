# Arch derivation and privacy

KITPro Linux Server is derived from Arch Linux package technology and uses
upstream Arch packages alongside KITPro packages and policy. KITPro is an
independent project. Arch Linux does not sponsor, endorse, or support KITPro
Linux Server. Upstream names and trademarks belong to their respective owners.
Package licenses remain applicable; release distribution must preserve required
license notices and satisfy source-distribution obligations.

KITPro's default server design includes no telemetry service or web management
UI. Health, kernel-status, rescue, and support-bundle commands run locally.
Support bundles are not uploaded automatically. The administrator chooses
whether to share a reviewed bundle.

Network operation still uses configured DNS/NTP services and the production
repository for updates. Optional SSH accepts public keys only. Final RC3
listener and service audits must confirm the shipped behavior.
