# KITPro install planner

`kitpro-install-planner` is the authoritative, side-effect-free planning library for
KITPro Linux Server. Distribution version `1.4.0` exposes planning API version `1`.

The package accepts a normalized, already validated install-spec v1 document, explicit
target facts, explicit verified source facts, and an installer version. `plan_v1()`
returns the unchanged backend plan schema v1 plus 13 fully ordered operations and a
digest over the complete result.

```python
from kitpro_install_planner import PlanningRequestV1, plan_v1

result = plan_v1(PlanningRequestV1(...))
canonical_bytes = result.canonical_bytes()
```

`plan_storage()` accepts ext4 storage schema v1, filesystem-aware schema v2, encrypted
root schema v3, and ordered manual-partition schema v4. Version 4 models supported EFI,
root, `/home`, `/var`, `/srv`, and swap roles with fixed or final remaining-space
allocation without changing the side-effect boundary.

Importing or calling this API performs no discovery, file access, process execution,
network access, clock read, environment lookup, or host modification. It does not
contain an installation engine.

Build the wheel from the KITPro Linux repository root:

```bash
python -m build --wheel --no-isolation planner
```

Consumers must pin `kitpro-install-planner==1.4.0`. A source checkout may use an
editable install of `planner/` for local development. Production packaging must use a
wheel built from a reviewed KITPro Linux commit and verify its recorded digest.
