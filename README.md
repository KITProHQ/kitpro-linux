# KITPro Linux Server source candidate

Local, unpublished source export for release-candidate validation.
Product source files are copied unchanged from the recorded engineering snapshot.
Production generation artifacts are external, public, hash-pinned build inputs.
Use the locked Arch worker described by ci/worker-lock.json. Build it locally
with `docker build -f ci/arch-worker.Containerfile -t kitpro-rc-worker .`.
Its base image and package snapshot are public and pinned; no private worker
registry or private repository is required.

Run `bash ci/phase6-fast.sh` for the included public test set.
Build with `python -m tools.production_media build --source . --generation GENERATION_DIRECTORY --output OUTPUT_DIRECTORY --build-id clean --release-policy config/releases/1.0-rc2.json`.
Run `python -m tools.production_media verify --manifest BUILD_MANIFEST --output VALIDATION_DIRECTORY --release-policy config/releases/1.0-rc2.json`.

This candidate has not been authorized for publication. Upstream package licenses
and source-distribution obligations remain applicable. See docs/rc2.
