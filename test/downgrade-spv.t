#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use Test::MockModule;

use QBitcoin::Const;
use QBitcoin::Crypto qw(hash256);
use Bitcoin::Serialized;
use Bitcoin::Block;
use QBitcoin::Downgrade;

# -----------------------------------------------------------------------
# Hand-built (non-witness) BTC transaction paying a P2PKH scriptPubKey.
# -----------------------------------------------------------------------
my $spk   = "\x76\xa9\x14" . ("\xab" x 20) . "\x88\xac";   # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
my $value = 50_000;                                        # satoshis
my $btc_tx =
    pack("V", 1) .                                         # version
    "\x01" .                                               # 1 input
    ("\x00" x 32) . pack("V", 0) . "\x00" . "\xff\xff\xff\xff" .  # input (empty scriptSig)
    "\x01" .                                               # 1 output
    pack("Q<", $value) . chr(length($spk)) . $spk .        # output
    pack("V", 0);                                          # locktime
my $txid = hash256($btc_tx);

my $blockhash = "\x77" x 32;
my $block = Bitcoin::Block->new({ height => 100, time => time(), merkle_root => $txid,        hash => $blockhash });
my $best  = Bitcoin::Block->new({ height => 110, time => time(), merkle_root => "\x00" x 32,  hash => "\x88" x 32 });

my $mock = Test::MockModule->new('Bitcoin::Block');
$mock->mock('find', sub {
    my $class = shift;
    my %a = @_;
    return ($a{hash} eq $blockhash ? $block : ()) if exists $a{hash};
    return ($best) if exists $a{'-sortby'};
    return ();
});

sub commit { QBitcoin::Downgrade->new({ btc_txid => $txid, btc_vout => 0, btc_value => $value, scriptpubkey => $spk, @_ }) }
sub proof  { QBitcoin::Downgrade->new({ btc_block_hash => $blockhash, btc_tx_num => 0, merkle_path => "", btc_tx_data => $btc_tx, @_ }) }

# -----------------------------------------------------------------------
# Serialization round-trips
# -----------------------------------------------------------------------
{
    my $c  = commit();
    my $c2 = QBitcoin::Downgrade->deserialize_commitment(Bitcoin::Serialized->new($c->serialize_commitment));
    is($c2->btc_txid,     $txid,  "commitment round-trip: btc_txid");
    is($c2->btc_vout,     0,      "commitment round-trip: btc_vout");
    is($c2->btc_value,    $value, "commitment round-trip: btc_value");
    is($c2->scriptpubkey, $spk,   "commitment round-trip: scriptpubkey");

    my $p  = proof();
    my $p2 = QBitcoin::Downgrade->deserialize_proof(Bitcoin::Serialized->new($p->serialize_proof));
    is($p2->btc_block_hash, $blockhash, "proof round-trip: btc_block_hash");
    is($p2->btc_tx_num,     0,          "proof round-trip: btc_tx_num");
    is($p2->merkle_path,    "",         "proof round-trip: merkle_path");
    is($p2->btc_tx_data,    $btc_tx,    "proof round-trip: btc_tx_data");
}

# -----------------------------------------------------------------------
# validate_spv
# -----------------------------------------------------------------------
is(proof()->validate_spv(commit()), 0, "valid SPV passes");

# value below committed
is(proof()->validate_spv(commit(btc_value => $value + 1)), -1, "output value below committed fails");
# accepts higher actual value than committed (user overpaid is fine)
is(proof()->validate_spv(commit(btc_value => $value - 1)), 0, "actual value above committed passes");

# wrong destination scriptPubKey
is(proof()->validate_spv(commit(scriptpubkey => "\x76\xa9\x14" . ("\xcd" x 20) . "\x88\xac")), -1,
    "wrong destination scriptPubKey fails");

# committed txid not matching the proof's tx
is(proof()->validate_spv(commit(btc_txid => "\x99" x 32)), -1, "committed txid mismatch fails");

# out-of-range vout
is(proof()->validate_spv(commit(btc_vout => 5)), -1, "missing output index fails");

# not deep enough: best only 3 blocks above
{
    my $shallow = Bitcoin::Block->new({ height => 100 + DOWNGRADE_BTC_CONFIRMS - 1, time => time(), merkle_root => "\x00" x 32, hash => "\x88" x 32 });
    my $m2 = Test::MockModule->new('Bitcoin::Block');
    $m2->mock('find', sub {
        my $class = shift; my %a = @_;
        return ($a{hash} eq $blockhash ? $block : ()) if exists $a{hash};
        return ($shallow) if exists $a{'-sortby'};
        return ();
    });
    is(proof()->validate_spv(commit()), -1, "insufficient BTC confirmations fails");
}

# wrong merkle path (tx not in block)
is(proof(merkle_path => "\x55" x 32)->validate_spv(commit()), -1, "bad merkle path fails");

done_testing();
