#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;

use QBitcoin::Config;
use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::Script qw(script_eval);
use QBitcoin::Script::OpCodes qw(:OPCODES);
use QBitcoin::Crypto qw(hash160 generate_keypair);
use QBitcoin::Address qw(wallet_import_format);
use QBitcoin::MyAddress;
use QBitcoin::TXO;
use QBitcoin::Transaction;
use QBitcoin::Downgrade::Build;

$config->{regtest} = 1;

my $sys = QBitcoin::MyAddress->new(private_key => wallet_import_format(generate_keypair(CRYPT_ALGO_ECDSA)->pk_serialize));
my $sys_pk = $sys->pubkey;
my $reclaim_id = "\x11" x 32;
my $spk = "\x76\xa9\x14" . ("\xcc" x 20) . "\x88\xac";
my $V   = 100 * DENOMINATOR;

# A freeze script with a TEST system pubkey (mirrors QBT_FREEZE_SCRIPT structure)
# so the IF (system spend) branch can be verified with a key we control.
my $test_freeze =
    OP_IF .
    OP_7 . OP_TX_TYPE . OP_EQUALVERIFY .
    chr(length($sys_pk)) . $sys_pk . OP_CHECKSIG .
    OP_ELSE .
    chr(4) . pack("V", DOWNGRADE_FREEZE_CSV) . OP_CSV . OP_DROP .
    OP_OUTPUTDATA . chr(1) . chr(0) . chr(1) . chr(32) . OP_SUBSTR .
    OP_OVER . OP_HASH256 . OP_EQUALVERIFY . OP_CHECKSIG .
    OP_ENDIF;

# --- make_sign_freeze_if: system signs the IF branch of a downgrade ---
{
    my $freeze_txo = QBitcoin::TXO->new_txo(tx_in => "\xaa" x 32, num => 0, value => $V,
        scripthash => hash160($test_freeze), data => $reclaim_id . $spk);
    my $out = QBitcoin::TXO->new_txo(value => $V, scripthash => hash160(QBT_DOWNGRADE_SCRIPT), data => $reclaim_id);
    my $commit = QBitcoin::Downgrade->new({ btc_txid => "\xcd" x 32, btc_vout => 0, btc_value => $V, scriptpubkey => $spk });
    my $tx = QBitcoin::Transaction->new(in => [{ txo => $freeze_txo }], out => [$out],
        tx_type => TX_TYPE_DOWNGRADE, fee => 0, down => $commit, hash => "\x01" x 32);

    $tx->make_sign_freeze_if($tx->in->[0], $sys, 0, $test_freeze);
    is(scalar @{$tx->in->[0]{siglist}}, 2, "freeze-IF siglist [sig, '\\x01']");
    is($tx->in->[0]{siglist}[1], "\x01", "IF selector is true");
    ok(script_eval($tx->in->[0]{siglist}, $test_freeze, $tx, 0),
        "freeze-IF: system sig + TX_TYPE_DOWNGRADE passes the IF branch");

    # A non-downgrade transaction must not pass the IF branch.
    my $proof = QBitcoin::Downgrade->new({ btc_block_hash => "\x00" x 32, btc_tx_num => 0, merkle_path => "", btc_tx_data => "\x00" });
    my $tx_burn = QBitcoin::Transaction->new(in => [{ txo => $freeze_txo }], out => [],
        tx_type => TX_TYPE_BURN, fee => 0, down => $proof, hash => "\x02" x 32);
    $tx_burn->make_sign_freeze_if($tx_burn->in->[0], $sys, 0, $test_freeze);
    ok(!script_eval($tx_burn->in->[0]{siglist}, $test_freeze, $tx_burn, 0),
        "freeze-IF: non-DOWNGRADE tx fails OP_TX_TYPE/EQUALVERIFY");
}

# --- build_downgrade_tx: structure of the constructed downgrade transaction ---
{
    my $freeze_txo = QBitcoin::TXO->new_txo(tx_in => "\xbb" x 32, num => 0, value => $V,
        scripthash => hash160(QBT_FREEZE_SCRIPT), data => $reclaim_id . $spk);
    my $tx = QBitcoin::Downgrade::Build->build_downgrade_tx($freeze_txo,
        system_address => $sys, btc_txid => "\xee" x 32, btc_vout => 3, btc_value => 99_000);
    ok($tx, "build_downgrade_tx returns a transaction");
    ok($tx->is_downgrade, "tx_type is DOWNGRADE");
    is($tx->fee, 0, "zero fee");
    is($tx->down->btc_txid,     "\xee" x 32, "commitment btc_txid");
    is($tx->down->btc_vout,     3,           "commitment btc_vout");
    is($tx->down->btc_value,    99_000,      "commitment btc_value");
    is($tx->down->scriptpubkey, $spk,        "commitment scriptpubkey copied from freeze data");
    is(scalar @{$tx->out}, 1, "one downgrade output");
    is($tx->out->[0]->scripthash, hash160(QBT_DOWNGRADE_SCRIPT), "output is the downgrade-output script");
    is($tx->out->[0]->data, $reclaim_id, "output carries the reclaim_id");
    is($tx->out->[0]->value, $V, "output value equals the freeze value");
    is(scalar @{$tx->in->[0]{siglist}}, 2, "freeze-IF siglist present");
}

done_testing();
