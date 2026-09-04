#! /usr/bin/env perl
use warnings;
use strict;

# The database path of QBitcoin::Coins->init: on a node restart the minted and burned
# totals are computed from the stored coinbase and txo tables. The burned total is the
# sum of the txo values spent by TX_TYPE_BURN transactions; txo spent by other
# transaction types must not be counted.

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use Test::MockModule;
use QBitcoin::Test::ORM qw(dbh);
use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::Block;
use QBitcoin::Transaction;
use QBitcoin::Coins;

$config->{regtest} = 1;

# Pretend the chain is loaded (in-core best block is not needed for the totals)
my $block_module = Test::MockModule->new('QBitcoin::Block');
$block_module->mock('blockchain_height', sub { 2 });

dbh->do("INSERT INTO `block` (height, time, hash, size, weight, merkle_root) VALUES (?, ?, ?, 100, 0, ?)",
    undef, $_, GENESIS_TIME + $_ * BLOCK_INTERVAL, chr($_) x 32, "\xcd" x 32) foreach 0 .. 2;
dbh->do("INSERT INTO `redeem_script` (id, hash, script) VALUES (1, ?, ?)", undef, "\x11" x 20, "\x51");

# Two coinbases (one of them with tx_out - only that one is confirmed in the chain)
dbh->do("INSERT INTO `transaction` (id, hash, block_height, block_pos, tx_type, size, fee) VALUES (1, ?, 1, 1, ?, 100, 0)",
    undef, "\xa1" x 32, TX_TYPE_COINBASE);
dbh->do("INSERT INTO `coinbase` (btc_out_num, btc_tx_hash, merkle_path, btc_tx_data, value, scripthash, tx_out, upgrade_level)" .
    " VALUES (0, ?, '', '', 100000, 1, 1, 0)", undef, "\xb1" x 32);
dbh->do("INSERT INTO `coinbase` (btc_out_num, btc_tx_hash, merkle_path, btc_tx_data, value, scripthash, tx_out, upgrade_level)" .
    " VALUES (0, ?, '', '', 50000, 1, NULL, 0)", undef, "\xb2" x 32);
# Coinbase output, spent by a standard transaction (must not count as burned)
dbh->do("INSERT INTO `transaction` (id, hash, block_height, block_pos, tx_type, size, fee) VALUES (2, ?, 1, 2, ?, 100, 100)",
    undef, "\xa2" x 32, TX_TYPE_STANDARD);
dbh->do("INSERT INTO `txo` (value, num, tx_in, tx_out, scripthash, data) VALUES (100000, 0, 1, 2, 1, '')");
# Downgrade transaction output, spent by a burn transaction
dbh->do("INSERT INTO `transaction` (id, hash, block_height, block_pos, tx_type, size, fee) VALUES (3, ?, 2, 1, ?, 100, 0)",
    undef, "\xa3" x 32, TX_TYPE_DOWNGRADE);
dbh->do("INSERT INTO `transaction` (id, hash, block_height, block_pos, tx_type, size, fee) VALUES (4, ?, 2, 2, ?, 100, 0)",
    undef, "\xa4" x 32, TX_TYPE_BURN);
dbh->do("INSERT INTO `txo` (value, num, tx_in, tx_out, scripthash, data) VALUES (30000, 0, 3, 4, 1, '')");
# Unspent output: not burned
dbh->do("INSERT INTO `txo` (value, num, tx_in, tx_out, scripthash, data) VALUES (69900, 0, 2, NULL, 1, '')");

QBitcoin::Coins->init();
is(QBitcoin::Coins->minted(), 100000, "minted loaded from the confirmed coinbase only");
is(QBitcoin::Coins->burned(), 30000, "burned loaded from the txo spent by the burn transaction only");
is(QBitcoin::Coins->total(), 70000, "total is minted minus burned");

done_testing();
