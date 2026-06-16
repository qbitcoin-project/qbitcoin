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
my $freeze_txid = "\xfa" x 32;
my $freeze_vout = 7;
my $marker = QBitcoin::Downgrade->downgrade_marker($freeze_txid, $freeze_vout);
my $marker_script = "\x6a" . chr(length($marker)) . $marker;
my $btc_tx =
    pack("V", 1) .                                         # version
    "\x01" .                                               # 1 input
    ("\x00" x 32) . pack("V", 0) . "\x00" . "\xff\xff\xff\xff" .  # input (empty scriptSig)
    "\x02" .                                               # 2 outputs
    pack("Q<", $value) . chr(length($spk)) . $spk .        # output
    pack("Q<", 0) . chr(length($marker_script)) . $marker_script .
    pack("V", 0);                                          # locktime
my $txid = hash256($btc_tx);

my $blockhash = "\x77" x 32;
my $block = Bitcoin::Block->new({ height => 100, time => time(), merkle_root => $txid,        hash => $blockhash });
my $best  = Bitcoin::Block->new({ height => 110, time => time(), merkle_root => "\x00" x 32,  hash => "\x88" x 32 });
my %block_by_hash = ($blockhash => $block);

my $mock = Test::MockModule->new('Bitcoin::Block');
$mock->mock('find', sub {
    my $class = shift;
    my %a = @_;
    return ($block_by_hash{$a{hash}} ? $block_by_hash{$a{hash}} : ()) if exists $a{hash};
    return ($best) if exists $a{'-sortby'};
    return ();
});

sub commit { QBitcoin::Downgrade->new({ freeze_txid => $freeze_txid, freeze_vout => $freeze_vout, btc_txid => $txid, btc_vout => 0, btc_value => $value, scriptpubkey => $spk, @_ }) }
sub proof  { QBitcoin::Downgrade->new({ btc_block_hash => $blockhash, btc_tx_num => 0, merkle_path => "", btc_tx_data => $btc_tx, @_ }) }

# -----------------------------------------------------------------------
# Serialization round-trips
# -----------------------------------------------------------------------
{
    my $c  = commit();
    my $c2 = QBitcoin::Downgrade->deserialize_commitment(Bitcoin::Serialized->new($c->serialize_commitment));
    is($c2->freeze_txid,  $freeze_txid, "commitment round-trip: freeze_txid");
    is($c2->freeze_vout,  $freeze_vout, "commitment round-trip: freeze_vout");
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

# BTC payment must identify the exact qbtc freeze output it serves.
{
    my $no_marker_tx =
        pack("V", 1) . "\x01" . ("\x00" x 32) . pack("V", 0) . "\x00" . "\xff\xff\xff\xff"
      . "\x01" . pack("Q<", $value) . chr(length($spk)) . $spk . pack("V", 0);
    my $no_marker_txid = hash256($no_marker_tx);
    my $no_marker_blockhash = "\x99" x 32;
    $block_by_hash{$no_marker_blockhash} = Bitcoin::Block->new({
        height => 100, time => time(), merkle_root => $no_marker_txid, hash => $no_marker_blockhash,
    });
    is(proof(btc_block_hash => $no_marker_blockhash, btc_tx_data => $no_marker_tx)->validate_spv(commit(btc_txid => $no_marker_txid)), -1,
        "missing freeze marker fails");
}
is(proof()->validate_spv(commit(freeze_vout => $freeze_vout + 1)), -1, "wrong freeze marker fails");

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
