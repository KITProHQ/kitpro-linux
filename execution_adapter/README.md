# KITPro execution adapter

`kitpro-execution-adapter` defines execution request and response API version 1. The
package validates privileged preflight evidence, keeps qualification and VM-live
authorization cryptographically separate, and exposes a narrow privileged service port.
It is not a command runner. Live commitment remains usable only through the trusted
guest service with an exact, single-use authorization.

The KITPro Linux repository supplies the backend port that calls the existing install
specification parser, planner, source verifier, and disk identity checks. The standalone
installer consumes the same package for request construction and status display.
