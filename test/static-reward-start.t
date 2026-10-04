#! /usr/bin/env perl
use warnings;
use strict;

# The halving of the static block reward is counted from the first block with the
# static reward (the upgrade stop), not from the genesis block.

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use Test::MockModule;
use QBitcoin::Test::ORM;
use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::Crypto qw(generate_keypair);
use QBitcoin::Address qw(wallet_import_format addresses_by_pubkey);
use QBitcoin::MyAddress;
use QBitcoin::Coins;
use QBitcoin::Block;
use QBitcoin::Generate;
use QBitcoin::Generate::Control;
use Bitcoin::Block;

$config->{regtest} = 1;
$config->{genesis} = 1;
$config->{genesis_reward} = GENESIS_REWARD;

# Emulate the btc-height upgrade stop at the given timeslot
my $stop;
my $btc_module = Test::MockModule->new('Bitcoin::Block');
$btc_module->mock('upgrade_stopped', sub { my (undef, $timeslot) = @_; defined($stop) && $timeslot >= $stop ? 1 : 0 });

my $pk = generate_keypair(CRYPT_ALGO_ECDSA);
my $pubkey = $pk->pubkey_by_privkey;
my ($address) = addresses_by_pubkey($pubkey, CRYPT_ALGO_ECDSA);
QBitcoin::MyAddress->create({
    private_key => wallet_import_format($pk->pk_serialize),
    address     => $address,
    staked      => 1,
});
QBitcoin::Coins->init();

my $halving = REWARD_HALVING * BLOCK_INTERVAL; # seconds
my $forced  = FORCE_BLOCKS * BLOCK_INTERVAL;   # empty blocks are allowed in forced slots only

my $time = GENESIS_TIME;
my $block0 = QBitcoin::Generate->generate($time);
ok($block0, "Genesis block generated");
is(QBitcoin::Block->static_reward($block0, $time + BLOCK_INTERVAL), 0, "No static reward during upgrade");
is(QBitcoin::Block->static_start, undef, "No static start during upgrade");

$stop = $time + $forced;
is(QBitcoin::Block->static_start, undef, "Static start is not defined until the first block with the reward");
is(QBitcoin::Block->static_reward($block0, $stop), STATIC_REWARD * FORCE_BLOCKS,
    "First block with the static reward is in epoch 0");
is(QBitcoin::Block->static_reward($block0, $stop + $halving), STATIC_REWARD * (REWARD_HALVING + FORCE_BLOCKS),
    "Epoch 0 wherever the first block is");

my $block1 = QBitcoin::Generate->generate($stop);
ok($block1, "Block 1 generated at the upgrade stop");
is(QBitcoin::Block->blockchain_height, 1, "Block 1 is the best block");
is(QBitcoin::Block->static_start, $stop, "Static start is the timeslot of the first block with the reward");
is(QBitcoin::Coins->minted(), STATIC_REWARD * FORCE_BLOCKS, "Static reward of block 1 minted");

# The halving boundary counted from the genesis block is still epoch 0 for us
is(QBitcoin::Block->static_reward($block1, $time + $halving), STATIC_REWARD * (REWARD_HALVING - FORCE_BLOCKS),
    "Full reward at the genesis-based halving boundary");
is(QBitcoin::Block->static_reward($block1, $stop + $halving - BLOCK_INTERVAL), STATIC_REWARD * (REWARD_HALVING - 1),
    "Full reward one slot before the first halving");
is(QBitcoin::Block->static_reward($block1, $stop + $halving), int(STATIC_REWARD / 2) * REWARD_HALVING,
    "Half reward since the first halving");
is(QBitcoin::Block->static_reward($block1, $stop + 2 * $halving), int(STATIC_REWARD / 4) * 2 * REWARD_HALVING,
    "Quarter reward since the second halving");

# Only the first block with the reward defines the start
my $block2 = QBitcoin::Generate->generate($stop + $forced);
ok($block2, "Block 2 generated");
is(QBitcoin::Block->blockchain_height, 2, "Block 2 is the best block");
is(QBitcoin::Block->static_start, $stop, "Static start not changed by the next block");
is(QBitcoin::Coins->minted(), STATIC_REWARD * 2 * FORCE_BLOCKS, "Static rewards of both blocks minted");
is(QBitcoin::Block->static_reward($block2, $stop + $halving), int(STATIC_REWARD / 2) * (REWARD_HALVING - FORCE_BLOCKS),
    "Half reward since the first halving for the next block too");
$block2->unconfirm();
is(QBitcoin::Block->blockchain_height, 1, "Block 2 unconfirmed");
is(QBitcoin::Block->static_start, $stop, "Static start not reset by unconfirm of the next block");

# Static start follows the best branch
$block1->unconfirm();
is(QBitcoin::Block->blockchain_height, 0, "Block 1 unconfirmed");
is(QBitcoin::Block->static_start, undef, "Static start reset on unconfirm of the first block");
is(QBitcoin::Coins->minted(), 0, "Static reward of block 1 unminted");
is(QBitcoin::Block->static_reward($block0, $stop + $forced), STATIC_REWARD * 2 * FORCE_BLOCKS,
    "Epoch 0 for the new first block");

# Regenerate block 1 in the same slot. Nobody has seen the stake of the unconfirmed
# block in this test, so withdraw it from the published-stake registry (it would
# otherwise prevent staking the same UTXO twice in the slot as self-equivocation)
QBitcoin::Generate::Control->unrecord_stake($stop, $block1->transactions->[0]);
undef $block1; # release the dropped block and its stake tx (the same outputs are recreated)
undef $block2;
my $block1a = QBitcoin::Generate->generate($stop);
ok($block1a, "Block 1 regenerated");
is(QBitcoin::Block->blockchain_height, 1, "Block 1 is the best block again");
is(QBitcoin::Block->static_start, $stop, "Static start set by the new first block");
is(QBitcoin::Coins->minted(), STATIC_REWARD * FORCE_BLOCKS, "Static reward of the new block 1 minted");

# After a restart the start is derived from the stored best branch
$block0->store();
$block1a->store();
is(QBitcoin::Block->first_static_height($block1a), 1, "First block with the static reward found in the database");
is(QBitcoin::Block->first_static_height($block0), undef, "No static reward in the database before the stop");

done_testing();
