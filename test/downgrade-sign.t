#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use Test::MockModule;

use QBitcoin::Config;
use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::Crypto qw(hash160 hash256 generate_keypair);
use QBitcoin::Address qw(wallet_import_format);
use QBitcoin::MyAddress;
use QBitcoin::Script qw(script_eval);
use QBitcoin::TXO;
use QBitcoin::Transaction;

$config->{regtest} = 1;

my $addr = QBitcoin::MyAddress->new(private_key => wallet_import_format(generate_keypair(CRYPT_ALGO_ECDSA)->pk_serialize));
my $reclaim_id = hash256($addr->pubkey);
my $spk = "\x76\xa9\x14" . ("\xab" x 20) . "\x88\xac";
my $V   = 100 * DENOMINATOR;

sub reclaim_tx {
    my ($freeze_script, $data) = @_;
    my $in_txo = QBitcoin::TXO->new_txo(tx_in => "\xaa" x 32, num => 0, value => $V,
        scripthash => hash160($freeze_script), data => $data);
    my $out = QBitcoin::TXO->new_txo(value => $V, num => 0, scripthash => "\x33" x 20);
    return QBitcoin::Transaction->new(in => [{ txo => $in_txo }], out => [$out], tx_type => TX_TYPE_STANDARD, fee => 0);
}

# --- make_sign_reclaim produces a valid ELSE-branch siglist ---
for my $case ([ "freeze", QBT_FREEZE_SCRIPT ], [ "downgrade output", QBT_DOWNGRADE_SCRIPT ]) {
    my ($name, $script) = @$case;
    my $tx = reclaim_tx($script, $reclaim_id . $spk);
    $tx->make_sign_reclaim($tx->in->[0], $addr, 0, $script);
    is(scalar @{$tx->in->[0]{siglist}}, 3, "$name: siglist [sig, pubkey, '']");
    is($tx->in->[0]{siglist}[2], "", "$name: ELSE selector is false");
    ok(script_eval($tx->in->[0]{siglist}, $script, $tx, 0), "$name: reclaim siglist passes ELSE branch");
}

# --- wrong reclaim_id (not our key) must not produce a spendable siglist ---
{
    my $tx = reclaim_tx(QBT_FREEZE_SCRIPT, ("\x99" x 32) . $spk);  # someone else's reclaim_id
    $tx->make_sign_reclaim($tx->in->[0], $addr, 0, QBT_FREEZE_SCRIPT);
    ok(!script_eval($tx->in->[0]{siglist}, QBT_FREEZE_SCRIPT, $tx, 0),
        "freeze: signing with a key that doesn't match reclaim_id fails the hash check");
}

# --- sign_transaction dispatches a freeze input to make_sign_reclaim ---
{
    my $mod = Test::MockModule->new('QBitcoin::MyAddress');
    $mod->mock('get_by_pubkeyhash', sub { my ($c, $h) = @_; return $h eq $reclaim_id ? $addr : undef });
    $mod->mock('get_by_hash',       sub { undef });

    my $tx = reclaim_tx(QBT_FREEZE_SCRIPT, $reclaim_id . $spk);
    $tx->sign_transaction;
    ok(script_eval($tx->in->[0]{siglist}, QBT_FREEZE_SCRIPT, $tx, 0),
        "sign_transaction: freeze reclaim input signed via reclaim_id lookup");
}

done_testing();
