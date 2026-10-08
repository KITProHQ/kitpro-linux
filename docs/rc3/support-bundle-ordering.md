# Canonical support-bundle member ordering

Members are unique normalized relative ASCII paths accepted by `safe_member_path`.
Compare their ASCII-encoded bytes lexicographically. `/` is the literal path
separator. Do not case-fold, apply locale collation, normalize unsafe names, or
use natural-number ordering. Reject duplicates and unsafe names.

`tools.support_bundle.canonical_member_order` owns this rule. The builder calls
it through the inspection helper's `order` command for manifest payload and tar
member lists. Manifest validation uses the same function. Archive verification
checks the original member sequence before extraction; inspection and safe-view
operate only on validated inventories. Changing the operator's locale is neither
required nor performed.

Each collection contains intentional timestamps, a random bundle ID, and live
collector output. Separate live collections are not promised identical hashes.
For identical staged member bytes and fixed archive metadata, the regression
matrix requires identical compressed archive hashes across locales. Independent
collections require identical logical member/manifest order and immutable fixture
member hashes. Health and secret-scan validation remain mandatory.

The regression matrix covers C, C.UTF-8, and en_US.UTF-8, plus another collation
locale if installed. It exercises creation, verification, inspection, safe view,
secret-scan status, and rejection of deliberately reversed archive order. Existing
live/offline, rescue, redaction, and inspector tests remain in the focused suite.

RC1: `INVALIDATED_BEFORE_ARTIFACT_COMPLETION`.
RC2: `INVALIDATED_BY_SUPPORT_BUNDLE_LOCALE_ORDERING_DEFECT`.
RC2 media and historical evidence are preserved. RC3 is not frozen until the
normal-locale physical regression and all pre-freeze gates pass.
