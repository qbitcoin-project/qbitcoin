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
use QBitcoin::Downgrade::Spv;

$config->{regtest} = 1;

my $now = 2_000_000_000;
my $old = $now - COINBASE_CONFIRM_TIME - 1000;
my $dbh = dbh();
my $dg_sh_hex = unpack("H*", hash160(QBT_DOWNGRADE_SCRIPT));
my $spk = "\x76\xa9\x14" . ("\xcc" x 20) . "\x88\xac";
my $spk_hex = unpack("H*", $spk);

$dbh->do("INSERT INTO block (height,time,hash,size,weight,merkle_root) VALUES (1,0,X'01',0,0,X'00')") or die $dbh->errstr;
$dbh->do("INSERT INTO redeem_script (id,hash) VALUES (10, X'$dg_sh_hex')") or die $dbh->errstr;

# A downgrade transaction with its typed commitment and an unspent output.
sub add_downgrade_tx {
    my ($id, $btc_txid) = @_;
    my $btc_txid_hex = unpack("H*", $btc_txid);
    my $freeze_txid_hex = sprintf("%02x", 0xf0 + $id) x 32;
    $dbh->do("INSERT INTO `transaction` (id,hash,block_height,block_pos,tx_type,size,fee) VALUES (?,?,1,?,?,10,0)",
        undef, $id, pack("C", 0xd0 + $id), $id, TX_TYPE_DOWNGRADE) or die $dbh->errstr;
    $dbh->do("INSERT INTO `downgrade` (tx_id,freeze_txid,freeze_vout,btc_txid,btc_vout,btc_value,scriptpubkey)"
           . " VALUES (?, X'$freeze_txid_hex', 0, X'$btc_txid_hex', 0, 5000, X'$spk_hex')",
        undef, $id) or die $dbh->errstr;
    $dbh->do("INSERT INTO txo (value,num,tx_in,tx_out,scripthash,data) VALUES (1000,0,?,NULL,10,X'1100')", undef, $id) or die $dbh->errstr;
}

add_downgrade_tx(1, "\xa1" x 32);   # deep SPV, unburned -> burnable
add_downgrade_tx(2, "\xa2" x 32);   # shallow SPV (not deep enough)
add_downgrade_tx(3, "\xa3" x 32);   # no SPV (pending detection)
add_downgrade_tx(4, "\xa4" x 32);   # deep SPV but already burned

for my $h (100, 108, 110) {
    $dbh->do("INSERT INTO btc_block (height,time,bits,nonce,version,chainwork,scanned,hash,merkle_root)"
           . " VALUES ($h,$old,0,0,1,$h,1,X'" . sprintf("%02x", $h) x 32 . "',X'00')") or die $dbh->errstr;
}

my $mp = "\x55" x 32;
my $td = "\x01\x02\x03";
sub add_spv {
    my ($dg_id, $height, $burn_tx_id) = @_;
    QBitcoin::Downgrade::Spv->create({
        downgrade_tx_id => $dg_id, btc_block_height => $height, btc_block_hash => ("\x99" x 32),
        btc_tx_num => 0, btc_tx_hash => ("\xaa" x 32), merkle_path => $mp, btc_tx_data => $td,
        defined $burn_tx_id ? (burn_tx_id => $burn_tx_id) : (),
    });
}
add_spv(1, 100, undef);   # deep, unburned
add_spv(2, 108, undef);   # shallow
add_spv(4, 100, 3);       # deep, burned (burn_tx_id set to an existing tx id)

# matched = block 110; max_height = 104. Only tx1 qualifies (deep, unspent, unburned).
my @new = QBitcoin::Downgrade::Spv->get_new($now);
is(scalar @new, 1, "one burnable SPV returned");
is($new[0]->downgrade_tx_id, 1, "the deep, unburned payment is returned");
is($new[0]->btc_block_hash, "\x99" x 32, "btc_block_hash carried");
is($new[0]->{dg_value}, 1000, "downgrade output value carried for burn building");

# pending_txids: only tx3 (no SPV row) is awaiting its BTC payment.
my $pending = QBitcoin::Downgrade::Spv->pending_txids();
is_deeply($pending, { ("\xa3" x 32) => 3 }, "pending_txids lists only the undetected downgrade");

# Reorg drops the pending SPV at/above the reverted height but keeps the burned one.
QBitcoin::Downgrade::Spv->delete_pending_above(99);
ok(!QBitcoin::Downgrade::Spv->fetch(downgrade_tx_id => 1), "pending SPV dropped on reorg");
ok( QBitcoin::Downgrade::Spv->fetch(downgrade_tx_id => 4), "burned SPV kept on reorg");

done_testing();
