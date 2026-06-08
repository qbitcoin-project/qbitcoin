#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use Test::MockModule;

use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::Crypto qw(hash256);
use QBitcoin::ValueUpgraded qw(downgrade_net);
use QBitcoin::TXO;
use QBitcoin::Transaction;
use QBitcoin::Downgrade;
use Bitcoin::Serialized;
use Bitcoin::Block;

$config->{regtest} = 1;

# Script-level checks are covered by trustless-downgrade.t; here we exercise the
# structural / commitment / floor / SPV glue in validate_downgrade & validate_burn.
my $txmod = Test::MockModule->new('QBitcoin::Transaction');
$txmod->mock('check_input_script', sub { 0 });

my $spk        = "\x76\xa9\x14" . ("\xab" x 20) . "\x88\xac";
my $reclaim_id = "\x11" x 20;            # EC user identity
my $V          = 100 * DENOMINATOR;      # qbtc value being downgraded
my $floor      = downgrade_net($V);

sub freeze_txo {
    QBitcoin::TXO->new_txo(tx_in => "\xaa" x 32, num => 0, value => $V,
        scripthash => QBitcoin::Transaction::QBT_FREEZE_SCRIPTHASH, data => $reclaim_id . $spk);
}
sub dg_out {
    QBitcoin::TXO->new_txo(value => $V,
        scripthash => QBitcoin::Transaction::QBT_DOWNGRADE_SCRIPTHASH, data => $reclaim_id);
}
sub commit { QBitcoin::Downgrade->new({ btc_txid => "\xcd" x 32, btc_vout => 0, btc_value => $floor, scriptpubkey => $spk, @_ }) }

sub dg_tx {
    my %o = @_;
    my $tx = QBitcoin::Transaction->new(
        tx_type => TX_TYPE_DOWNGRADE, fee => 0, hash => "\x01" x 32,
        in  => [{ txo => $o{in}  // freeze_txo() }],
        out => [ $o{out} // dg_out() ],
        down => $o{down} // commit(),
    );
    return $tx;
}

# ----------------------- validate_downgrade -----------------------
is(dg_tx()->validate_downgrade, 0, "valid downgrade passes");

is(dg_tx(down => commit(btc_value => $floor - 1))->validate_downgrade, -1, "btc_value below floor fails");
is(dg_tx(down => commit(scriptpubkey => "\x00" x 25))->validate_downgrade, -1, "scriptpubkey != freeze destination fails");
is(dg_tx(out => QBitcoin::TXO->new_txo(value => $V, scripthash => QBitcoin::Transaction::QBT_DOWNGRADE_SCRIPTHASH, data => "\x22" x 20))->validate_downgrade, -1,
    "output reclaim_id mismatch fails");
is(dg_tx(out => QBitcoin::TXO->new_txo(value => $V - 1, scripthash => QBitcoin::Transaction::QBT_DOWNGRADE_SCRIPTHASH, data => $reclaim_id))->validate_downgrade, -1,
    "output value != input fails");
is(dg_tx(in => QBitcoin::TXO->new_txo(tx_in => "\xaa" x 32, num => 0, value => $V, scripthash => "\x33" x 20, data => $reclaim_id . $spk))->validate_downgrade, -1,
    "input not a freeze output fails");
{
    my $tx = dg_tx(); $tx->{fee} = 1;
    is($tx->validate_downgrade, -1, "non-zero fee fails");
}

# ----------------------- validate_burn -----------------------
# Real (non-witness) BTC tx paying $spk; block with merkle_root = txid.
my $btc_tx =
    pack("V", 1) . "\x01" . ("\x00" x 32) . pack("V", 0) . "\x00" . "\xff\xff\xff\xff"
  . "\x01" . pack("Q<", $floor) . chr(length($spk)) . $spk . pack("V", 0);
my $txid      = hash256($btc_tx);
my $blockhash = "\x77" x 32;
my $block = Bitcoin::Block->new({ height => 100, time => time(), merkle_root => $txid,       hash => $blockhash });
my $best  = Bitcoin::Block->new({ height => 110, time => time(), merkle_root => "\x00" x 32, hash => "\x88" x 32 });

my $blkmod = Test::MockModule->new('Bitcoin::Block');
$blkmod->mock('find', sub {
    my $class = shift; my %a = @_;
    return ($a{hash} eq $blockhash ? $block : ()) if exists $a{hash};
    return ($best) if exists $a{'-sortby'};
    return ();
});

my $src_hash = "\xde" x 32;
my $src_commit = QBitcoin::Downgrade->new({ btc_txid => $txid, btc_vout => 0, btc_value => $floor, scriptpubkey => $spk });
my $src_tx = QBitcoin::Transaction->new(tx_type => TX_TYPE_DOWNGRADE, down => $src_commit, hash => $src_hash);
$txmod->mock('get', sub { my ($c, $h) = @_; return defined($h) && $h eq $src_hash ? $src_tx : undef });

sub proof { QBitcoin::Downgrade->new({ btc_block_hash => $blockhash, btc_tx_num => 0, merkle_path => "", btc_tx_data => $btc_tx, @_ }) }
sub burn_txo { QBitcoin::TXO->new_txo(tx_in => $src_hash, num => 0, value => $V, scripthash => QBitcoin::Transaction::QBT_DOWNGRADE_SCRIPTHASH) }
sub burn_tx {
    my %o = @_;
    QBitcoin::Transaction->new(tx_type => TX_TYPE_BURN, fee => $V, hash => "\x02" x 32,
        in => [{ txo => $o{in} // burn_txo() }], out => [], down => $o{down} // proof());
}

is(burn_tx()->validate_burn, 0, "valid burn passes");
is(burn_tx(down => proof(merkle_path => "\x55" x 32))->validate_burn, -1, "bad merkle path fails");
is(burn_tx(in => QBitcoin::TXO->new_txo(tx_in => $src_hash, num => 0, value => $V, scripthash => "\x44" x 20))->validate_burn, -1,
    "burn input not a downgrade output fails");
{
    my $tx = burn_tx(); push @{$tx->{out}}, dg_out();
    is($tx->validate_burn, -1, "burn with outputs fails");
}
{
    # source tx unknown
    $txmod->mock('get', sub { undef });
    $txmod->mock('find', sub { () });
    is(burn_tx()->validate_burn, -1, "burn with unknown source downgrade fails");
}

done_testing();
