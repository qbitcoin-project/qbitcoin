#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use QBitcoin::Test::ORM qw(dbh);
use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::Crypto qw(hash256);
use QBitcoin::Transaction;
use QBitcoin::Downgrade;
use QBitcoin::Downgrade::Commitment;
use Bitcoin::Serialized;

$config->{regtest} = 1;

# DOWNGRADE carries a commitment, BURN carries an SPV proof, serialized right
# after tx_type and committed to the tx hash. A stored tx re-attaches the payload
# from the `downgrade` side table (QBitcoin::DowngradeData).

sub _vs { pack("C", length($_[0])) . $_[0] }

my $spk      = "\x76\xa9\x14" . ("\xab" x 20) . "\x88\xac";  # P2PKH scriptPubKey
my $txid     = "\xcd" x 32;
my $sig_elem = pack("CC", 1, 1) . pack("H*", "3044022012340220abcd");
my $redeem   = "\x52\xae"; # dummy redeem
my $prev     = "\xab" x 32;
my $input    = $prev . pack("C", 0) . pack("C", 1) . _vs($sig_elem) . _vs($redeem);

# ---------------------------------------------------------------------------
# DOWNGRADE commitment round-trip through the transaction wire
# ---------------------------------------------------------------------------
{
    my $commit = QBitcoin::Downgrade->new({ btc_txid => $txid, btc_vout => 0, btc_value => 50_000, scriptpubkey => $spk });
    my $out    = pack("Q<", 3 * DENOMINATOR) . _vs("\x11" x 20) . _vs("");
    my $wire =
        pack("c", TX_TYPE_DOWNGRADE) . $commit->serialize_commitment
      . pack("C", 1) . $input
      . pack("C", 1) . $out;

    my $tx = QBitcoin::Transaction->deserialize(Bitcoin::Serialized->new($wire));
    ok($tx, "DOWNGRADE deserialized");
    ok($tx->is_downgrade, "is_downgrade true");
    ok($tx->down, "commitment attached");
    is($tx->down->btc_txid,     $txid,   "commitment btc_txid");
    is($tx->down->btc_vout,     0,       "commitment btc_vout");
    is($tx->down->btc_value,    50_000,  "commitment btc_value");
    is($tx->down->scriptpubkey, $spk,    "commitment scriptpubkey");
    is(unpack("H*", $tx->hash), unpack("H*", hash256($wire)), "tx hash covers commitment");

    $tx->{in} = []; $tx->{out} = [];
    my $reser = $tx->serialize;
    is(unpack("H*", substr($reser, 0, 1 + length($commit->serialize_commitment))),
       unpack("H*", pack("c", TX_TYPE_DOWNGRADE) . $commit->serialize_commitment),
       "serialize: commitment right after tx_type");
}

# ---------------------------------------------------------------------------
# BURN proof round-trip through the transaction wire
# ---------------------------------------------------------------------------
{
    my $btc_tx_data = pack("V", 1) . "\x00" x 10;       # opaque dummy
    my $proof = QBitcoin::Downgrade->new({
        btc_block_hash => "\x77" x 32, btc_tx_num => 3, merkle_path => "\x55" x 32, btc_tx_data => $btc_tx_data,
    });
    my $wire =
        pack("c", TX_TYPE_BURN) . $proof->serialize_proof
      . pack("C", 1) . $input
      . pack("C", 0);

    my $tx = QBitcoin::Transaction->deserialize(Bitcoin::Serialized->new($wire));
    ok($tx, "BURN deserialized");
    ok($tx->is_burn, "is_burn true");
    is($tx->down->btc_block_hash, "\x77" x 32,  "proof btc_block_hash");
    is($tx->down->btc_tx_num,     3,            "proof btc_tx_num");
    is($tx->down->merkle_path,    "\x55" x 32,  "proof merkle_path");
    is($tx->down->btc_tx_data,    $btc_tx_data, "proof btc_tx_data");
    is(unpack("H*", $tx->hash), unpack("H*", hash256($wire)), "tx hash covers proof");
}

# truncated commitment is rejected
ok(!defined QBitcoin::Transaction->deserialize(Bitcoin::Serialized->new(pack("c", TX_TYPE_DOWNGRADE) . ("\xcd" x 10))),
    "truncated downgrade commitment rejected");

# ---------------------------------------------------------------------------
# Persistence: typed commitment store/fetch and FK cascade
# ---------------------------------------------------------------------------
{
    my $dbh = dbh();
    $dbh->do("INSERT INTO block (height,time,hash,size,weight,merkle_root) VALUES (0,0,X'00',0,0,X'00')") or die $dbh->errstr;
    $dbh->do("INSERT INTO `transaction` (id,hash,block_height,block_pos,tx_type,size,fee) VALUES (1,X'aa',0,0,?,10,0)",
        undef, TX_TYPE_DOWNGRADE) or die $dbh->errstr;

    QBitcoin::Downgrade::Commitment->create({ tx_id => 1, btc_txid => $txid, btc_vout => 2, btc_value => 99, scriptpubkey => $spk });
    my ($row) = QBitcoin::Downgrade::Commitment->find(tx_id => 1);
    ok($row, "commitment stored and fetched");
    is($row->btc_txid,     $txid, "stored commitment btc_txid round-trips");
    is($row->btc_vout,     2,     "stored commitment btc_vout round-trips");
    is($row->btc_value,    99,    "stored commitment btc_value round-trips");
    is($row->scriptpubkey, $spk,  "stored commitment scriptpubkey round-trips");

    $dbh->do("DELETE FROM `transaction` WHERE id = 1") or die $dbh->errstr;
    my ($gone) = QBitcoin::Downgrade::Commitment->fetch(tx_id => 1);
    ok(!$gone, "commitment removed by ON DELETE CASCADE");
}

done_testing();
