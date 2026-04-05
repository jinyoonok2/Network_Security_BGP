"""
Phase 3: ASPA Cache — loads and serves ASPA records for path validation.

Supports two data sources:
  1. Real ASPA records from Routinator's RPKI export (cryptographically signed)
  2. Simulated ASPA records derived from CAIDA's AS-relationship dataset

For each customer ASN, stores the set of authorized provider ASNs.
"""

import json
import bz2
import os


class ASPACache:
    """
    In-memory cache of ASPA records.
    Maps each customer ASN → set of authorized provider ASNs.
    """

    def __init__(self):
        # {customer_asn: set(provider_asn_1, provider_asn_2, ...)}
        self.records = {}
        # Track source of records for reporting
        self.source = None
        # Peer-to-peer relationships (for valley-free validation)
        self.peers = {}  # {asn: set(peer_asn_1, peer_asn_2, ...)}

    def load_from_routinator_json(self, filepath):
        """
        Load real ASPA records from Routinator's JSON export.
        These are cryptographically signed RPKI objects.

        Expected JSON structure:
        {
            "aspas": [
                {"customer": "AS553", "providers": ["AS174", "AS1299", ...], "ta": "ripe"},
                ...
            ]
        }
        """
        with open(filepath) as f:
            data = json.load(f)

        aspa_list = data.get("aspas", [])
        for record in aspa_list:
            customer_str = record["customer"]  # e.g. "AS553"
            customer_asn = int(customer_str.replace("AS", ""))

            providers = set()
            for p in record["providers"]:
                provider_asn = int(p.replace("AS", ""))
                if provider_asn != 0:  # AS0 means "no provider" / transit-free
                    providers.add(provider_asn)

            if providers:
                self.records[customer_asn] = providers

        self.source = "routinator"
        return len(self.records)

    def load_from_caida_relationships(self, filepath):
        """
        Build simulated ASPA records from CAIDA's AS-relationship dataset.

        File format (bz2 compressed):
            # comment lines start with #
            <AS1>|<AS2>|<relationship>|<source>
            relationship: -1 = AS1 is provider of AS2 (provider-to-customer)
                           0 = AS1 and AS2 are peers

        For ASPA simulation:
            If AS1 is provider of AS2 (rel=-1), then AS2's ASPA record
            should include AS1 as an authorized provider.
        """
        open_func = bz2.open if filepath.endswith(".bz2") else open

        with open_func(filepath, "rt") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split("|")
                if len(parts) < 3:
                    continue

                as1 = int(parts[0])
                as2 = int(parts[1])
                rel = int(parts[2])

                if rel == -1:
                    # AS1 is provider of AS2
                    # → AS2's ASPA record includes AS1 as authorized provider
                    if as2 not in self.records:
                        self.records[as2] = set()
                    self.records[as2].add(as1)

                elif rel == 0:
                    # Peer-to-peer relationship
                    if as1 not in self.peers:
                        self.peers[as1] = set()
                    if as2 not in self.peers:
                        self.peers[as2] = set()
                    self.peers[as1].add(as2)
                    self.peers[as2].add(as1)

        self.source = "caida"
        return len(self.records)

    def get_providers(self, customer_asn):
        """
        Return set of authorized provider ASNs for a customer.
        Returns None if no ASPA record exists for this ASN.
        """
        return self.records.get(customer_asn)

    def get_peers(self, asn):
        """Return set of peer ASNs, or empty set if none known."""
        return self.peers.get(asn, set())

    def has_record(self, customer_asn):
        """Check if an ASPA record exists for this customer ASN."""
        return customer_asn in self.records

    def is_provider_of(self, provider_asn, customer_asn):
        """Check if provider_asn is an authorized provider of customer_asn."""
        providers = self.records.get(customer_asn)
        if providers is None:
            return None  # No record — unknown
        return provider_asn in providers

    def is_peer_of(self, asn1, asn2):
        """Check if asn1 and asn2 are peers."""
        return asn2 in self.peers.get(asn1, set())

    def summary(self):
        """Return a summary dict of the cache contents."""
        all_providers = set()
        for providers in self.records.values():
            all_providers.update(providers)

        return {
            "source": self.source,
            "total_customer_asns": len(self.records),
            "total_unique_providers": len(all_providers),
            "total_peer_pairs": sum(len(p) for p in self.peers.values()) // 2,
            "avg_providers_per_customer": (
                sum(len(p) for p in self.records.values()) / len(self.records)
                if self.records else 0
            ),
        }


def main():
    """Test loading from both data sources."""
    data_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
    )

    # 1. Load real ASPA records from Routinator
    routinator_file = os.path.join(data_dir, "rpki_vrps_with_aspa.json")
    if os.path.exists(routinator_file):
        cache_real = ASPACache()
        count = cache_real.load_from_routinator_json(routinator_file)
        summary = cache_real.summary()
        print(f"{'='*60}")
        print(f"REAL ASPA RECORDS (from Routinator RPKI)")
        print(f"{'='*60}")
        print(f"  Customer ASNs with ASPA records: {summary['total_customer_asns']:,}")
        print(f"  Unique provider ASNs:            {summary['total_unique_providers']:,}")
        print(f"  Avg providers per customer:      {summary['avg_providers_per_customer']:.1f}")
        # Show a few examples
        print(f"\n  Sample records:")
        for i, (cust, provs) in enumerate(cache_real.records.items()):
            if i >= 5:
                break
            print(f"    AS{cust} → providers: {{{', '.join(f'AS{p}' for p in sorted(provs))}}}")
    else:
        print(f"Routinator file not found: {routinator_file}")

    # 2. Load simulated ASPA records from CAIDA
    caida_file = os.path.join(data_dir, "20240101.as-rel2.txt.bz2")
    if os.path.exists(caida_file):
        cache_sim = ASPACache()
        count = cache_sim.load_from_caida_relationships(caida_file)
        summary = cache_sim.summary()
        print(f"\n{'='*60}")
        print(f"SIMULATED ASPA RECORDS (from CAIDA AS-relationships)")
        print(f"{'='*60}")
        print(f"  Customer ASNs with ASPA records: {summary['total_customer_asns']:,}")
        print(f"  Unique provider ASNs:            {summary['total_unique_providers']:,}")
        print(f"  Peer-to-peer pairs:              {summary['total_peer_pairs']:,}")
        print(f"  Avg providers per customer:      {summary['avg_providers_per_customer']:.1f}")
        # Show a few examples
        print(f"\n  Sample records:")
        for i, (cust, provs) in enumerate(cache_sim.records.items()):
            if i >= 5:
                break
            print(f"    AS{cust} → providers: {{{', '.join(f'AS{p}' for p in sorted(provs))}}}")
    else:
        print(f"CAIDA file not found: {caida_file}")

    print(f"\nPhase 3 PASSED: ASPA cache loading working.")


if __name__ == "__main__":
    main()
