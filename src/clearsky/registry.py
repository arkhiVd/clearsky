"""Detector registry.

A detector is any object with:
  id: str          - stable unique name, e.g. "ec2.unused_eip"
  title: str       - human readable name
  run(session, region) -> list[Finding]

New detectors self-register via the @register decorator; importing the
detectors package is enough to populate the registry.
"""

DETECTORS: dict[str, object] = {}


def register(cls):
    instance = cls()
    if instance.id in DETECTORS:
        raise ValueError(f"duplicate detector id: {instance.id}")
    DETECTORS[instance.id] = instance
    return cls


def all_detectors() -> list:
    # Import for side effect: detector modules register themselves.
    from clearsky import detectors  # noqa: F401

    return list(DETECTORS.values())
