#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use QBitcoin::Test::ORM qw(dbh);
use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::Crypto qw(hash160);
use QBitcoin::Downgrade;
use QBitcoin::Downgrade::Spv;

$config->{regtest} = 1;

my $now = 2_000_000_000;
my $old = $now - COINBASE_CONFIRM_TIME - 1000;
my $dbh = dbh();
my $dg_sh_hex = unpack("H*", hash160(QBT_DOWNGRADE_SCRIPT));
my $spk = "\x76\xa9\x14" . ("\xcc" x 20) . "\x88\xac";

# qbtc block + downgrade transactions (each with its committed BTC txid in the
# `downgrade` payload and an unspent downgrade output).
$dbh->do("INSERT INTO block (height,time,hash,size,weight,merkle_root) VALUES (1,0,X'01',0,0,X'00')") or die $dbh->errstr;
$dbh->do("INSERT INTO redeem_script (id,hash) VALUES (10, X'$dg_sh_hex')") or die $dbh->errstr;

sub add_downgrade_tx {
    my ($id, $btc_txid, $unspent) = @_;
    $dbh->do("INSERT INTO `transaction` (id,hash,block_height,block_pos,tx_type,size,fee) VALUES (?,?,1,?,?,10,0)",
        undef, $id, pack("C", 0xd0 + $id), $id, TX_TYPE_DOWNGRADE) or die $dbh->errstr;
    my $commit = QBitcoin::Downgrade->new({ btc_txid => $btc_txid, btc_vout => 0, btc_value => 5000, scriptpubkey => $spk });
    my $payload_hex = unpack("H*", $commit->serialize_commitment);
    $dbh->do("INSERT INTO `downgrade` (tx_id, payload) VALUES (?, X'$payload_hex')", undef, $id) or die $dbh->errstr;
    $dbh->do("INSERT INTO txo (value,num,tx_in,tx_out,scripthash,data) VALUES (1000,0,?," . ($unspent ? "NULL" : "1") . ",10,X'1100')",
        undef, $id) or die $dbh->errstr;
}

add_downgrade_tx(1, "\xa1" x 32, 1);   # will get an SPV, deep, unspent
add_downgrade_tx(2, "\xa2" x 32, 1);   # will get an SPV, shallow
add_downgrade_tx(3, "\xa3" x 32, 1);   # no SPV yet (pending)

# BTC blocks: 100 and 108 host payments; 110 is the deepest old block ("matched").
for my $h (100, 108, 110) {
    $dbh->do("INSERT INTO btc_block (height,time,bits,nonce,version,chainwork,scanned,hash,merkle_root)"
           . " VALUES ($h,$old,0,0,1,$h,1,X'" . sprintf("%02x", $h) x 32 . "',X'00')") or die $dbh->errstr;
}

my $mp = "\x55" x 32;
my $td = "\x01\x02\x03";
QBitcoin::Downgrade::Spv->create({ downgrade_tx_id => 1, btc_block_height => 100, btc_tx_num => 0, btc_tx_hash => ("\xaa" x 32), merkle_path => $mp, btc_tx_data => $td });
QBitcoin::Downgrade::Spv->create({ downgrade_tx_id => 2, btc_block_height => 108, btc_tx_num => 0, btc_tx_hash => ("\xbb" x 32), merkle_path => $mp, btc_tx_data => $td });

# matched = block 110; max_height = 110 - 6 = 104. tx1 (btc 100) confirmed, tx2 (btc 108) not.
my @new = QBitcoin::Downgrade::Spv->get_new($now);
is(scalar @new, 1, "one confirmed downgrade SPV returned");
is($new[0]->downgrade_tx_id, 1, "the deep (btc height 100) payment is the confirmed one");
is($new[0]->{dg_value}, 1000, "downgrade output value carried for burn building");

my @again = QBitcoin::Downgrade::Spv->get_new($now);
is(scalar @again, 0, "already-produced SPV not returned again");

# pending_txids: only downgrade tx 3 (no SPV row yet) is awaiting its BTC payment.
my $pending = QBitcoin::Downgrade::Spv->pending_txids();
is_deeply($pending, { ("\xa3" x 32) => 3 }, "pending_txids lists only the downgrade without an SPV");

done_testing();
