# Reproducibility

Published attacks pin the target paper version, upstream source revision or archive
hash, relevant dependencies, and attack code. Reproducers expose a documented quick
mode when useful and a full mode that generates legitimate data, runs the attack,
signs a previously unsigned message, invokes the ordinary verifier, and performs a
negative control.

Reports include commands, processor and worker count, wall-clock runtime, peak RAM,
trial count, and success count. Long computations include checkpointing or a safe
evidence replay without embedding unavailable secret labels.
