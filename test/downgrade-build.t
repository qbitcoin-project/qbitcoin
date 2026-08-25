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
use QBitcoin::Crypto qw(hash160 sha256 generate_keypair pk_import);
use QBitcoin::Address qw(wallet_import_format);
use QBitcoin::MyAddress;
use QBitcoin::TXO;
use QBitcoin::Transaction;
use QBitcoin::Downgrade::Build;

$config->{regtest} = 1;

sub addr_of { QBitcoin::MyAddress->new(private_key => wallet_import_format($_[0]->pk_serialize)) }

# Three test federation addresses (and an outsider) for an ad-hoc 2-of-3 freeze script.
my @sys      = map { addr_of(generate_keypair(CRYPT_ALGO_ECDSA)) } 1 .. 3;
my $outsider = addr_of(generate_keypair(CRYPT_ALGO_ECDSA));
my $reclaim_id = "\x11" x 32;
my $spk = "\x76\xa9\x14" . ("\xcc" x 20) . "\x88\xac";
my $V   = 100 * DENOMINATOR;

# A freeze script with TEST federation pubkeys (mirrors QBT_FREEZE_SCRIPT
# structure: 2-of-3 CHECKMULTISIG, keys sorted) so the IF (system spend) branch
# can be verified with keys we control.
my $test_freeze =
    OP_IF .
    OP_7 . OP_TX_TYPE . OP_EQUALVERIFY .
    OP_2 . join("", map { chr(length($_)) . $_ } sort map { $_->pubkey } @sys) . OP_3 . OP_CHECKMULTISIG .
    OP_ELSE .
    chr(4) . pack("V", DOWNGRADE_FREEZE_CSV) . OP_CSV . OP_DROP .
    OP_OUTPUTDATA . chr(1) . chr(0) . chr(1) . chr(32) . OP_SUBSTR .
    OP_OVER . OP_HASH256 . OP_EQUALVERIFY . OP_CHECKSIG .
    OP_ENDIF;

# --- make_sign_freeze_if: the federation signs the IF branch of a downgrade ---
{
    my $freeze_txo = QBitcoin::TXO->new_txo(tx_in => "\xaa" x 32, num => 0, value => $V,
        scripthash => hash160($test_freeze), data => $reclaim_id . $spk);
    my $out = QBitcoin::TXO->new_txo(value => $V, scripthash => hash160(QBT_DOWNGRADE_SCRIPT), data => $reclaim_id);
    my $commit = QBitcoin::Downgrade->new({
        freeze_txid => $freeze_txo->tx_in, freeze_vout => $freeze_txo->num,
        btc_txid => "\xcd" x 32, btc_vout => 0, btc_value => $V, scriptpubkey => $spk,
    });
    my $tx = QBitcoin::Transaction->new(in => [{ txo => $freeze_txo }], out => [$out],
        tx_type => TX_TYPE_DOWNGRADE, fee => 0, down => $commit, hash => "\x01" x 32);

    sub if_sign {
        my ($tx, $signers) = @_;
        $tx->make_sign_freeze_if($tx->in->[0], $signers, 0, $test_freeze);
        return $tx->in->[0]{siglist};
    }

    my $siglist = if_sign($tx, [ @sys[0, 1] ]);
    is(scalar @$siglist, 3, "freeze-IF siglist [sig, sig, '\\x01']");
    ok(defined $siglist->[0] && defined $siglist->[1], "both signatures defined");
    is($siglist->[2], "\x01", "IF selector is true");
    ok(script_eval($siglist, $test_freeze, $tx, 0),
        "freeze-IF: 2 federation sigs + TX_TYPE_DOWNGRADE pass the IF branch");

    # Any pair of the three works, whatever the argument order (sigs are ordered
    # by pubkey to match the sorted script keys).
    ok(script_eval(if_sign($tx, [ @sys[1, 2] ]), $test_freeze, $tx, 0), "pair (2,3) passes");
    ok(script_eval(if_sign($tx, [ @sys[2, 0] ]), $test_freeze, $tx, 0), "pair (3,1) passes in any argument order");

    # 1-of-3 is not enough; a doubled key is not two signers; outsiders don't count.
    ok(!script_eval(if_sign($tx, $sys[0]), $test_freeze, $tx, 0), "a single signature fails");
    ok(!script_eval(if_sign($tx, [ @sys[0, 0] ]), $test_freeze, $tx, 0), "the same key twice fails");
    ok(!script_eval(if_sign($tx, [ $outsider, $sys[0] ]), $test_freeze, $tx, 0), "an outsider signature fails");

    # A non-downgrade transaction must not pass the IF branch.
    my $proof = QBitcoin::Downgrade->new({ btc_block_hash => "\x00" x 32, btc_tx_num => 0, merkle_path => "", btc_tx_data => "\x00" });
    my $tx_burn = QBitcoin::Transaction->new(in => [{ txo => $freeze_txo }], out => [],
        tx_type => TX_TYPE_BURN, fee => 0, down => $proof, hash => "\x02" x 32);
    ok(!script_eval(if_sign($tx_burn, [ @sys[0, 1] ]), $test_freeze, $tx_burn, 0),
        "freeze-IF: non-DOWNGRADE tx fails OP_TX_TYPE/EQUALVERIFY");
}

# --- build_downgrade_tx: structure of the constructed downgrade transaction ---
{
    # Two of the three regtest federation addresses, from the derivable dev keys
    # (see QBT_FREEZE_PUBKEYS in QBitcoin::BlockchainParams).
    my @fed = map { addr_of(pk_import(sha256("QBTC:REGTEST:FREEZE:$_"), CRYPT_ALGO_ECDSA)) } qw(A B);
    my $freeze_txo = QBitcoin::TXO->new_txo(tx_in => "\xbb" x 32, num => 0, value => $V,
        scripthash => hash160(QBT_FREEZE_SCRIPT), data => $reclaim_id . $spk);
    my $tx = QBitcoin::Downgrade::Build->build_downgrade_tx($freeze_txo,
        system_addresses => \@fed, btc_txid => "\xee" x 32, btc_vout => 3, btc_value => 99_000);
    ok($tx, "build_downgrade_tx returns a transaction");
    ok($tx->is_downgrade, "tx_type is DOWNGRADE");
    is($tx->fee, 0, "zero fee");
    is($tx->down->freeze_txid,  "\xbb" x 32, "commitment freeze_txid");
    is($tx->down->freeze_vout,  0,           "commitment freeze_vout");
    is($tx->down->btc_txid,     "\xee" x 32, "commitment btc_txid");
    is($tx->down->btc_vout,     3,           "commitment btc_vout");
    is($tx->down->btc_value,    99_000,      "commitment btc_value");
    is($tx->down->scriptpubkey, $spk,        "commitment scriptpubkey copied from freeze data");
    is(scalar @{$tx->out}, 1, "one downgrade output");
    is($tx->out->[0]->scripthash, hash160(QBT_DOWNGRADE_SCRIPT), "output is the downgrade-output script");
    is($tx->out->[0]->data, $reclaim_id, "output carries the reclaim_id");
    is($tx->out->[0]->value, $V, "output value equals the freeze value");
    is(scalar @{$tx->in->[0]{siglist}}, 3, "freeze-IF siglist present");
    ok(script_eval($tx->in->[0]{siglist}, QBT_FREEZE_SCRIPT, $tx, 0),
        "the built pin passes the real QBT_FREEZE_SCRIPT with the regtest federation keys");
    ok(!QBitcoin::Downgrade::Build->build_downgrade_tx($freeze_txo,
        system_address => $fed[0], btc_txid => "\xee" x 32, btc_vout => 3, btc_value => 99_000),
        "build_downgrade_tx requires the system_addresses arrayref");

    # The unsigned construction is the same deterministic object the signed one
    # is made of: identical signing preimage, no signatures yet.
    my $unsigned = QBitcoin::Downgrade::Build->build_downgrade_unsigned($freeze_txo,
        btc_txid => "\xee" x 32, btc_vout => 3, btc_value => 99_000);
    ok($unsigned, "build_downgrade_unsigned returns a transaction");
    ok(!$unsigned->in->[0]{siglist}, "unsigned pin carries no siglist");
    is($unsigned->sign_data(0, SIGHASH_ALL), $tx->sign_data(0, SIGHASH_ALL),
        "signing preimage matches the signed pin's");
}

done_testing();
