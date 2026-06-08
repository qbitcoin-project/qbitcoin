#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use QBitcoin::Test::ORM qw(dbh);
use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::Downgrade::Spv;

$config->{regtest} = 1;

my $now = 2_000_000_000;
my $old = $now - COINBASE_CONFIRM_TIME - 1000;
my $dbh = dbh();

# One qbtc block to host the downgrade transactions.
$dbh->do("INSERT INTO block (height,time,hash,size,weight,merkle_root) VALUES (1,0,X'01',0,0,X'00')") or die $dbh->errstr;
$dbh->do("INSERT INTO `transaction` (id,hash,block_height,block_pos,tx_type,size,fee) VALUES (1,X'd1',1,0,6,10,0)") or die $dbh->errstr;
$dbh->do("INSERT INTO `transaction` (id,hash,block_height,block_pos,tx_type,size,fee) VALUES (2,X'd2',1,1,6,10,0)") or die $dbh->errstr;

# BTC blocks: 100 and 108 host payments; 110 is the deepest old block ("matched").
for my $h (100, 108, 110) {
    $dbh->do("INSERT INTO btc_block (height,time,bits,nonce,version,chainwork,scanned,hash,merkle_root)"
           . " VALUES ($h,$old,0,0,1,$h,1,X'" . sprintf("%02x", $h) x 32 . "',X'00')") or die $dbh->errstr;
}

# SPV for downgrade tx 1 at btc height 100 (deep), tx 2 at btc height 108 (shallow).
my $mp  = "\x55" x 32;
my $td  = "\x01\x02\x03";
QBitcoin::Downgrade::Spv->create({ downgrade_tx_id => 1, btc_block_height => 100, btc_tx_num => 0, btc_tx_hash => ("\xaa" x 32), merkle_path => $mp, btc_tx_data => $td });
QBitcoin::Downgrade::Spv->create({ downgrade_tx_id => 2, btc_block_height => 108, btc_tx_num => 0, btc_tx_hash => ("\xbb" x 32), merkle_path => $mp, btc_tx_data => $td });

# matched = block 110 (deepest with old time); max_height = 110 - 6 = 104.
# tx1 (btc 100 <= 104) is confirmed; tx2 (btc 108 > 104) is not yet.
my @new = QBitcoin::Downgrade::Spv->get_new($now);
is(scalar @new, 1, "one confirmed downgrade SPV returned");
is($new[0]->downgrade_tx_id, 1, "the deep (btc height 100) payment is the confirmed one");
is($new[0]->btc_tx_hash, "\xaa" x 32, "btc_tx_hash round-trips");
is($new[0]->merkle_path, $mp, "merkle_path round-trips");

# Already-produced entries are not returned again (in-memory dedup).
my @again = QBitcoin::Downgrade::Spv->get_new($now);
is(scalar @again, 0, "already-produced SPV not returned again");

# Nothing confirmed if no BTC block is old enough.
my @none = QBitcoin::Downgrade::Spv->get_new($old);
is(scalar @none, 0, "nothing returned before COINBASE_CONFIRM_TIME elapses");

done_testing();
