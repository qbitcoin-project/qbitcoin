#! /usr/bin/env perl
use warnings;
use strict;

# Pool self-spends must not mint upgrade coinbases: an output paying
# QBT_LOCK_SCRIPT is excluded from deposit detection when the transaction spends
# the pool itself (an input's scriptSig is the BIP141-forced QBT_LOCK_SCRIPTSIG)
# or carries a strict-format QDG1 downgrade marker. Both signs live in the
# non-witness transaction data, so the rule holds for the scanner and for the
# wire validation (Coinbase::deserialize) alike.

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::Crypto qw(hash160);
use QBitcoin::Script::OpCodes qw(:OPCODES);
use QBitcoin::Coinbase;
use QBitcoin::Downgrade;
use Bitcoin::Serialized;
use Bitcoin::Transaction;

$config->{regtest} = 1;

# ------------------------------------------------------------------
# Raw legacy-layout btc transaction: version | vin | vout | locktime.
# ------------------------------------------------------------------
my $prevout_num = 0;
sub build_tx {
    my ($ins, $outs) = @_;
    my $data = pack("V", 1) . pack("C", scalar @$ins);
    foreach my $script_sig (@$ins) {
        # unique prevout per input keeps test transactions distinct
        $data .= ("\xaa" x 28) . pack("V", $prevout_num++) . pack("V", 0);
        $data .= varstr($script_sig) . "\xff\xff\xff\xff";
    }
    $data .= pack("C", scalar @$outs);
    $data .= pack("Q<", $_->[0]) . varstr($_->[1]) foreach @$outs;
    $data .= pack("V", 0);
    my $obj = Bitcoin::Serialized->new($data);
    my $tx = Bitcoin::Transaction->deserialize($obj);
    die "test btc tx build failed\n" unless $tx && !$obj->length;
    return $tx;
}

sub opret { OP_RETURN . pack("C", length($_[0])) . $_[0] }

# P2PKH-style scriptSig: push(71-byte sig), push(33-byte pubkey); enough for the
# depositor-identity derivation in get_scripthash.
my $pubkey    = "\x02" . "\x11" x 32;
my $p2pkh_sig = pack("C", 0x47) . ("\x01" x 0x47) . pack("C", 0x21) . $pubkey;

my $user_script = "\x76\xa9\x14" . ("\xbb" x 20) . "\x88\xac";     # unrelated P2PKH output
my $marker      = QBitcoin::Downgrade->downgrade_marker("\xcc" x 32, 1);
my $dest20      = hash160("\x10\x11");                              # OP_RETURN destination

# ------------------------------------------------------------------
# Baselines: ordinary deposits still mint.
# ------------------------------------------------------------------
my $deposit = build_tx([ $p2pkh_sig ], [ [ 1000, QBT_LOCK_SCRIPT ] ]);
ok(defined QBitcoin::Coinbase->get_scripthash($deposit, 0), "deposit with P2PKH input mints");

my $deposit_dest = build_tx([ $p2pkh_sig ], [ [ 1000, QBT_LOCK_SCRIPT ], [ 0, opret($dest20) ] ]);
is(QBitcoin::Coinbase->get_scripthash($deposit_dest, 0), $dest20, "deposit destination from OP_RETURN");

# ------------------------------------------------------------------
# Exclusion by input: the scriptSig of a pool spend is exactly QBT_LOCK_SCRIPTSIG.
# ------------------------------------------------------------------
my $release = build_tx(
    [ QBT_LOCK_SCRIPTSIG ],
    [ [ 900, $user_script ], [ 100, QBT_LOCK_SCRIPT ], [ 0, opret($marker) ] ],
);
is(QBitcoin::Coinbase->get_scripthash($release, 1), undef, "release change is not a deposit");

my $cpfp = build_tx([ QBT_LOCK_SCRIPTSIG ], [ [ 100, QBT_LOCK_SCRIPT ] ]);
is(QBitcoin::Coinbase->get_scripthash($cpfp, 0), undef, "unmarked pool spend (CPFP child) is excluded by input");

my $mixed = build_tx([ $p2pkh_sig, QBT_LOCK_SCRIPTSIG ], [ [ 100, QBT_LOCK_SCRIPT ] ]);
is(QBitcoin::Coinbase->get_scripthash($mixed, 0), undef, "pool input among others still excludes");

# Near-miss scriptSig (same shape, different redeem hash) is not a pool spend:
# the deposit still mints to its OP_RETURN destination.
my $near_sig = "\x22\x00\x20" . ("\xab" x 32);
my $near = build_tx([ $near_sig ], [ [ 100, QBT_LOCK_SCRIPT ], [ 0, opret($dest20) ] ]);
is(QBitcoin::Coinbase->get_scripthash($near, 0), $dest20, "near-miss scriptSig does not exclude");

# ------------------------------------------------------------------
# Exclusion by marker: a marked transaction is a system one even without a
# recognizable pool input (e.g. a cold-storage refill must co-spend the pool,
# but the marker alone already protects).
# ------------------------------------------------------------------
my $refill = build_tx([ $p2pkh_sig ], [ [ 100, QBT_LOCK_SCRIPT ], [ 0, opret($marker) ] ]);
is(QBitcoin::Coinbase->get_scripthash($refill, 0), undef, "marked transaction is excluded without a pool input");

# ------------------------------------------------------------------
# Marker strictness: only OP_RETURN with a direct push of exactly
# magic(4) + version(1) + txid(32) + vout(4) = 41 bytes counts.
# ------------------------------------------------------------------
my $qdg1_32 = "QDG1\x01" . ("\xdd" x 27);   # 32 bytes, QDG1-prefixed
my $dep32 = build_tx([ $p2pkh_sig ], [ [ 100, QBT_LOCK_SCRIPT ], [ 0, opret($qdg1_32) ] ]);
is(QBitcoin::Coinbase->get_scripthash($dep32, 0), $qdg1_32,
    "32-byte QDG1-prefixed destination is not a marker: deposit mints to it");

my $qdg1_41 = build_tx([ $p2pkh_sig ], [ [ 100, QBT_LOCK_SCRIPT ], [ 0, opret("QDG1\x01" . ("\xdd" x 36)) ] ]);
is(QBitcoin::Coinbase->get_scripthash($qdg1_41, 0), undef,
    "41-byte QDG1 payload as destination excludes the deposit (deliberate donation)");

my $xdg1_41 = "XDG1\x01" . ("\xdd" x 36);   # 41 bytes, wrong magic
my $dep41 = build_tx([ $p2pkh_sig ], [ [ 100, QBT_LOCK_SCRIPT ], [ 0, opret($xdg1_41) ] ]);
is(QBitcoin::Coinbase->get_scripthash($dep41, 0), $xdg1_41, "41-byte non-QDG1 destination still mints");

my $qdg2_41 = "QDG1\x02" . ("\xdd" x 36);   # 41 bytes, wrong version
my $depv2 = build_tx([ $p2pkh_sig ], [ [ 100, QBT_LOCK_SCRIPT ], [ 0, opret($qdg2_41) ] ]);
is(QBitcoin::Coinbase->get_scripthash($depv2, 0), $qdg2_41, "unknown marker version does not exclude");

# The marker in a pool spend must not be misread as an upgrade destination for
# the change output right before it.
my $release_adjacent = build_tx(
    [ QBT_LOCK_SCRIPTSIG ],
    [ [ 900, $user_script ], [ 100, QBT_LOCK_SCRIPT ], [ 0, opret($marker) ] ],
);
is(QBitcoin::Coinbase->get_scripthash($release_adjacent, 1), undef, "marker after change is not a destination");

# ------------------------------------------------------------------
# Wire path: Coinbase::deserialize derives the scripthash through the same rule,
# so a coinbase crafted from a release change output is rejected.
# ------------------------------------------------------------------
sub coinbase_payload {
    my ($tx, $out_num) = @_;
    return pack("C", 1) . ("\xee" x 32) . pack("C", 0) . pack("C", $out_num)
         . varstr($tx->data) . varstr("");
}
my $crafted = QBitcoin::Coinbase->deserialize(Bitcoin::Serialized->new(coinbase_payload($release, 1)), 0);
is($crafted, undef, "wire coinbase from a release change output is rejected");

my $honest = QBitcoin::Coinbase->deserialize(Bitcoin::Serialized->new(coinbase_payload($deposit_dest, 0)), 0);
ok(defined $honest, "wire coinbase from an honest deposit is accepted");
is($honest && $honest->scripthash, $dest20, "wire coinbase scripthash matches the OP_RETURN destination");

done_testing();
