"""
Phase 4: ASPA Path Verification Engine.

Implements the ASPA (Autonomous System Provider Authorization) verification
algorithm based on draft-ietf-sidrops-aspa-verification. Checks each AS path
for valley-free compliance and unauthorized hops.

Valid AS paths follow the valley-free property:
    UP*  PEER?  DOWN*
    (zero or more customer→provider hops,
     at most one peer link,
     zero or more provider→customer hops)

A violation of this pattern (e.g., UP→DOWN→UP) indicates a route leak.
"""

from enum import Enum


class ASPAResult(Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


def remove_prepends(as_path):
    """
    Strip consecutive duplicate ASNs caused by AS path prepending.

    Example: [3356, 3356, 174, 13335] → [3356, 174, 13335]
    """
    if not as_path:
        return []
    clean = [as_path[0]]
    for asn in as_path[1:]:
        if asn != clean[-1]:
            clean.append(asn)
    return clean


def classify_hop(as_a, as_b, aspa_cache):
    """
    Classify the routing direction from as_a to as_b.

    Uses ASPA records and peer information to determine if the hop is:
      - "up":           as_b is an authorized provider of as_a (customer→provider)
      - "down":         as_a is an authorized provider of as_b (provider→customer)
      - "peer":         as_a and as_b are peers
      - "not-provider": at least one side has an ASPA record that does NOT
                        authorize this relationship → potential route leak
      - "unknown":      neither side has ASPA records, cannot determine
    """
    a_providers = aspa_cache.get_providers(as_a)
    b_providers = aspa_cache.get_providers(as_b)

    # UP: as_b is in as_a's authorized provider set
    if a_providers is not None and as_b in a_providers:
        return "up"

    # DOWN: as_a is in as_b's authorized provider set
    if b_providers is not None and as_a in b_providers:
        return "down"

    # PEER: lateral relationship
    if aspa_cache.is_peer_of(as_a, as_b):
        return "peer"

    # At least one side has a record but the other isn't listed
    if a_providers is not None or b_providers is not None:
        return "not-provider"

    # No ASPA data for either AS
    return "unknown"


def verify_as_path(as_path, aspa_cache):
    """
    Run ASPA verification on a full AS path.

    Args:
        as_path: list of integer ASNs [origin, ..., last_hop]
        aspa_cache: ASPACache instance with loaded ASPA/CAIDA records

    Returns:
        (ASPAResult, list_of_violations)
        Each violation is a tuple (hop_index, reason_string).
    """
    clean = remove_prepends(as_path)

    # Single-hop or empty paths are trivially valid
    if len(clean) <= 1:
        return ASPAResult.VALID, []

    # --- Classify every hop ---
    hops = []
    for i in range(len(clean) - 1):
        direction = classify_hop(clean[i], clean[i + 1], aspa_cache)
        hops.append((i, clean[i], clean[i + 1], direction))

    # --- Detect violations ---
    violations = []
    has_coverage = False   # at least one hop is classifiable
    all_covered = True     # every hop is classifiable

    # 1. Flag unauthorized hops (ASPA record exists but neighbor not listed)
    for i, as_a, as_b, direction in hops:
        if direction == "not-provider":
            violations.append(
                (i, f"unauthorized: AS{as_a}->AS{as_b} not authorized by ASPA")
            )
            has_coverage = True
        elif direction == "unknown":
            all_covered = False
        else:
            has_coverage = True

    # 2. Valley-free structural check on the classified hops
    #    Valid pattern: up* peer? down*
    #    phase: 0 = UP, 1 = PEER, 2 = DOWN
    phase = 0
    for i, as_a, as_b, direction in hops:
        if direction in ("unknown", "not-provider"):
            continue  # already flagged or unresolvable

        if direction == "up":
            if phase == 2:
                violations.append(
                    (i, f"valley: AS{as_a}->AS{as_b} UP after DOWN")
                )
            elif phase == 1:
                violations.append(
                    (i, f"valley: AS{as_a}->AS{as_b} UP after PEER")
                )

        elif direction == "down":
            if phase <= 1:
                phase = 2  # transition to DOWN phase

        elif direction == "peer":
            if phase == 1:
                violations.append(
                    (i, f"double-peer: AS{as_a}->AS{as_b}")
                )
            elif phase == 2:
                violations.append(
                    (i, f"valley: AS{as_a}->AS{as_b} PEER after DOWN")
                )
            else:
                phase = 1

    # --- Determine final result ---
    if violations:
        return ASPAResult.INVALID, violations

    if not has_coverage:
        return ASPAResult.UNKNOWN, []

    if not all_covered:
        # Some hops classified, none violated, but gaps remain
        return ASPAResult.UNKNOWN, []

    return ASPAResult.VALID, []


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def _self_test():
    """Quick smoke test with a mock ASPA cache."""

    class MockCache:
        """Minimal mock for testing."""
        def __init__(self, records, peers=None):
            self.records = records      # {customer: set(providers)}
            self.peers = peers or {}    # {asn: set(peer_asns)}

        def get_providers(self, asn):
            return self.records.get(asn)

        def is_peer_of(self, a, b):
            return b in self.peers.get(a, set())

    print("Running aspa_verifier self-tests …")

    # ---- Test 1: Clean upstream path (all UP) ----
    cache = MockCache({1: {2}, 2: {3}, 3: {4}})
    result, viols = verify_as_path([1, 2, 3, 4], cache)
    assert result == ASPAResult.VALID, f"Test 1 failed: {result}"
    print("  [PASS] Test 1: valid upstream path")

    # ---- Test 2: Valley violation (UP → DOWN → UP) ----
    cache = MockCache({1: {2}, 2: set(), 3: {4}}, peers={2: {3}, 3: {2}})
    # Path: 1→2 UP, 2→3 PEER, 3→4 UP
    result, viols = verify_as_path([1, 2, 3, 4], cache)
    assert result == ASPAResult.INVALID, f"Test 2 failed: {result}"
    print(f"  [PASS] Test 2: valley after PEER ({len(viols)} violations)")

    # ---- Test 3: UP then DOWN (valid) ----
    cache = MockCache({1: {2}, 3: {2}})  # AS1→AS2 UP, AS2→AS3 DOWN (AS2 is AS3's provider)
    result, viols = verify_as_path([1, 2, 3], cache)
    assert result == ASPAResult.VALID, f"Test 3 failed: {result}"
    print("  [PASS] Test 3: valid UP then DOWN")

    # ---- Test 4: Prepend stripping ----
    cache = MockCache({1: {2}, 2: {3}})
    result, viols = verify_as_path([1, 1, 1, 2, 2, 3], cache)
    assert result == ASPAResult.VALID, f"Test 4 failed: {result}"
    print("  [PASS] Test 4: prepending stripped correctly")

    # ---- Test 5: Single AS path ----
    cache = MockCache({})
    result, viols = verify_as_path([42], cache)
    assert result == ASPAResult.VALID, f"Test 5 failed: {result}"
    print("  [PASS] Test 5: single-AS path is VALID")

    # ---- Test 6: All unknown ----
    cache = MockCache({})
    result, viols = verify_as_path([10, 20, 30], cache)
    assert result == ASPAResult.UNKNOWN, f"Test 6 failed: {result}"
    print("  [PASS] Test 6: no ASPA data → UNKNOWN")

    # ---- Test 7: Unauthorized hop ----
    cache = MockCache({1: {99}})  # AS1's provider is AS99, NOT AS2
    result, viols = verify_as_path([1, 2], cache)
    assert result == ASPAResult.INVALID, f"Test 7 failed: {result}"
    print(f"  [PASS] Test 7: unauthorized hop detected ({viols[0][1]})")

    # ---- Test 8: From the guideline example ----
    # Path: AS1→AS2→AS3→AS4
    # AS1 providers: {AS2}, AS2 providers: {AS5}, AS3 providers: {AS4}
    cache = MockCache({1: {2}, 2: {5}, 3: {4}})
    result, viols = verify_as_path([1, 2, 3, 4], cache)
    assert result == ASPAResult.INVALID, f"Test 8 failed: {result}"
    print(f"  [PASS] Test 8: guideline example → INVALID ({len(viols)} violations)")
    for v in viols:
        print(f"         hop {v[0]}: {v[1]}")

    print("\nAll self-tests passed ✓")


if __name__ == "__main__":
    _self_test()
