#! /usr/bin/env perl
use warnings;
use strict;

# The database path of QBitcoin::Coins->genesis_scripthashes: on a node restarted
# after the genesis block dropped out of core, the genesis-reward scripthashes are
# loaded from the stored genesis stake transaction. Kept in a separate test file
# because the result is cached for the process lifetime (genesis-reward.t exercises
# the in-core path).

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use QBitcoin::Test::ORM qw(dbh);
use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::Crypto qw(hash160);
use QBitcoin::Script::OpCodes qw(:OPCODES);
use QBitcoin::Script qw(op_pushdata);
use QBitcoin::Transaction;
use QBitcoin::Block;
use QBitcoin::Coins;

$config->{regtest} = 1;
$config->{genesis_reward} = 5000;

my $genesis_script     = op_pushdata(pack("v", 1)) . OP_DROP . OP_1;
my $genesis_scripthash = hash160($genesis_script);

# Stored genesis block with an inputless stake transaction holding the genesis reward
dbh->do("INSERT INTO `block` (height, time, hash, size, weight, merkle_root) VALUES (0, ?, ?, 100, 0, ?)",
    undef, GENESIS_TIME, "\xab" x 32, "\xcd" x 32);
dbh->do("INSERT INTO `transaction` (id, hash, block_height, block_pos, tx_type, size, fee) VALUES (1, ?, 0, 0, ?, 100, -5000)",
    undef, "\xee" x 32, TX_TYPE_STAKE);
dbh->do("INSERT INTO `redeem_script` (id, hash, script) VALUES (1, ?, ?)",
    undef, $genesis_scripthash, $genesis_script);
dbh->do("INSERT INTO `txo` (value, num, tx_in, scripthash, data) VALUES (5000, 0, 1, 1, '')");

is_deeply(QBitcoin::Coins->genesis_scripthashes, { $genesis_scripthash => 1 },
    "genesis scripthash loaded from the stored genesis block");

done_testing();
