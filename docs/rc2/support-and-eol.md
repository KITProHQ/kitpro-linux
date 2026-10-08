# KITPro Linux Server 1.0 support planning

Standard support is planned for 12 months from final 1.0 publication.
RC2 does not start the support clock. Final publication has not occurred;
there is no support-start or EOL timestamp to announce yet.

RC users should retain backups, report reproducible defects, and include a
locally inspected, sanitized support bundle when useful. Review a bundle before
sharing it. No automatic upload is required.

A 14-day Beelink burn-in begins only after RC2 qualification passes. Daily review
covers health, failed units, storage, and journal errors. The period includes at
least three warm reboots, two clean shutdown/cold-boot cycles, SSH, password-backed
sudo, a live support bundle, a rescue boot, and a qualified generation update if
one is available. Do not fabricate a kernel update to satisfy this requirement.

Final release requires completed burn-in and explicit publication authorization.
