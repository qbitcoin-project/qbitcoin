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
use QBitcoin::Burn;
use Bitcoin::Serialized;

$config->{regtest} = 1;

# ---------------------------------------------------------------------------
# Burn transactions carry a 32-byte reverse pointer to the Bitcoin transaction
# that released the corresponding BTC during a downgrade (AML traceability,
# QBTC->BTC). It is serialized right after tx_type, committed to the tx hash,
# and persisted in the side table `burn_txid` (QBitcoin::Burn).
# ---------------------------------------------------------------------------

my $btc_txid = pack("H*", "cd" x 32);

# --- A test vector produced by the downgrade service (QBTCDowngrade::BurnTx) ---
# Layout: tx_type(05) . btc_txid(32) . varint(1 input) . prev_txid(32) . vout(0)
#         . siglist(1) . varstr(sig) . varstr(redeem_script) . varint(0 outputs)
my $prev_txid = pack("H*", "ab" x 32);
my $sig_elem  = pack("CC", 1, 1) . pack("H*", "3044022012340220abcd"); # sighash, algo, dummy DER
my $redeem    = pack("C", 2) . "\x01\x02" . "\xac"; # dummy P2PK-ish redeem script

my $wire =
    pack("c", TX_TYPE_BURN)
  . $btc_txid
  . pack("C", 1)                                 # 1 input (varint)
  . $prev_txid . pack("C", 0)                    # prev txid + vout
  . pack("C", 1)                                 # siglist count
  . pack("C", length($sig_elem)) . $sig_elem     # varstr(sig)
  . pack("C", length($redeem))   . $redeem       # varstr(redeem script)
  . pack("C", 0);                                # 0 outputs

# --- deserialize ---
my $tx = QBitcoin::Transaction->deserialize(Bitcoin::Serialized->new($wire));
ok($tx, "burn transaction deserialized");
is($tx->tx_type, TX_TYPE_BURN, "tx_type is TX_TYPE_BURN");
ok($tx->is_burn, "is_burn true");
is(unpack("H*", $tx->btc_txid), "cd" x 32, "btc_txid deserialized correctly");
is(scalar @{$tx->in_raw}, 1, "one input parsed after btc_txid");

# hash commits to btc_txid: recompute over the exact wire bytes
is(unpack("H*", $tx->hash), unpack("H*", hash256($wire)), "tx hash covers btc_txid");

# --- serialize places btc_txid right after tx_type ---
$tx->{in} = [];                       # in_raw was populated by deserialize; serialize uses `in`
my $reser = $tx->serialize;
is(unpack("H*", substr($reser, 0, 1)),  unpack("H*", pack("c", TX_TYPE_BURN)), "serialize: tx_type first");
is(unpack("H*", substr($reser, 1, 32)), "cd" x 32, "serialize: btc_txid right after tx_type");

# --- a burn transaction truncated within btc_txid must be rejected ---
my $short = pack("c", TX_TYPE_BURN) . ("\xcd" x 31);
ok(!defined QBitcoin::Transaction->deserialize(Bitcoin::Serialized->new($short)),
    "truncated btc_txid (31 bytes) rejected");

# ---------------------------------------------------------------------------
# Persistence: QBitcoin::Burn store/load and FK cascade
# ---------------------------------------------------------------------------
my $dbh = dbh();
$dbh->do("INSERT INTO block (height,time,hash,size,weight,merkle_root) VALUES (0,0,X'00',0,0,X'00')")
    or die $dbh->errstr;
$dbh->do("INSERT INTO `transaction` (id,hash,block_height,block_pos,tx_type,size,fee) VALUES (1,X'aa',0,0,?,10,0)",
    undef, TX_TYPE_BURN) or die $dbh->errstr;

QBitcoin::Burn->create({ tx_id => 1, btc_txid => $btc_txid });
my ($row) = QBitcoin::Burn->fetch(tx_id => 1);
ok($row, "burn_txid row stored and fetched");
is(unpack("H*", $row->{btc_txid}), "cd" x 32, "stored btc_txid round-trips");

$dbh->do("DELETE FROM `transaction` WHERE id = 1") or die $dbh->errstr;
my ($gone) = QBitcoin::Burn->fetch(tx_id => 1);
ok(!$gone, "burn_txid row removed by ON DELETE CASCADE");

done_testing();
