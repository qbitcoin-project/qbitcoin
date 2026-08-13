#! /usr/bin/env perl
use warnings;
use strict;

# Genesis-reward coins are stake-only in the wallet, like an address staked for
# a foreign owner: they provide stake weight (staked_utxo) but are never part of
# the balance (my_utxo / getbalance), and the RPC marks the genesis address
# "stakeonly". This covers:
# - priming the genesis scripthashes when the genesis block is first confirmed
#   (its outputs get their wallet roles before the block enters the best branch)
# - wallet-utxo roles: staked genesis address => stake source only; unstaked =>
#   tracked but neither balance nor stake source
# - stakeaddress / unstakeaddress re-rolling the stake-only outputs
# - the stakeonly flag in listmyaddresses / getaddressinfo
# - a normal wallet address stays in the balance and unmarked

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use Test::MockModule;
use List::Util qw(sum0);
use QBitcoin::Test::ORM;
use QBitcoin::Test::BlockSerialize qw(block_hash);
use QBitcoin::Test::Send qw(send_tx send_raw_tx send_block $last_tx);
use QBitcoin::Const;
use QBitcoin::RPC::Const;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::ProtocolState qw(mempool_synced blockchain_synced);
use QBitcoin::Transaction;
use QBitcoin::TXO;
use QBitcoin::Block;
use QBitcoin::Generate;
use QBitcoin::Crypto qw(generate_keypair);
use QBitcoin::Address qw(wallet_import_format addresses_by_pubkey);
use QBitcoin::MyAddress;
use QBitcoin::Wallet::UTXO ();
use QBitcoin::Coins;

$config->{regtest} = 1;
$config->{genesis} = 1;
$config->{genesis_reward} = GENESIS_REWARD;

my $transaction_module = Test::MockModule->new('QBitcoin::Transaction');
$transaction_module->mock('validate_coinbase', sub { 0 });
my $static_reward = 200000000;
my $block_module = Test::MockModule->new('QBitcoin::Block');
$block_module->mock('static_reward', sub { $static_reward });

# Minimal RPC handler for testing cmd_* without the HTTP layer (see delegation.t)
{
    package TestRPC;
    use warnings;
    use strict;
    use QBitcoin::Accessors qw(mk_accessors);
    use Role::Tiny::With;
    with 'QBitcoin::RPC::Validate';
    with 'QBitcoin::RPC::Commands';
    mk_accessors(qw(cmd args _rpc_result _rpc_error _rpc_error_code));
    sub new { bless {}, shift }
    sub response_ok    { $_[0]->_rpc_result($_[1] // "ok"); 0 }
    sub response_error { $_[0]->_rpc_error($_[1]); $_[0]->_rpc_error_code($_[2]); -1 }
}

sub rpc {
    my ($cmd, @args) = @_;
    my $rpc = TestRPC->new;
    $rpc->cmd($cmd);
    $rpc->args(\@args);
    if ($rpc->validate(TestRPC->params($cmd)) != 0) {
        return $rpc;
    }
    my $func = "cmd_$cmd";
    $rpc->$func;
    return $rpc;
}

my $pk = generate_keypair(CRYPT_ALGO_ECDSA);
my ($gen_address) = addresses_by_pubkey($pk->pubkey_by_privkey, CRYPT_ALGO_ECDSA);
my $genesis_addr = QBitcoin::MyAddress->create({
    private_key => wallet_import_format($pk->pk_serialize),
    address     => $gen_address,
    staked      => 1,
});
my $genesis_sh = scalar $genesis_addr->scripthash;

QBitcoin::Coins->init();

# --- genesis block: reward coins become stake-only wallet outputs -------------

block_hash("a0");
my $block0 = QBitcoin::Generate->generate(GENESIS_TIME);
ok($block0, "Genesis block generated");
my $genesis_value = sum0(map { $_->value } @{$block0->transactions->[0]->out});
ok($genesis_value > 0, "genesis reward paid to the wallet address");

is_deeply(QBitcoin::Coins->genesis_scripthashes, { $genesis_sh => 1 },
    "genesis scripthashes known after the genesis block confirmed");

is(sum0(map { $_->value } QBitcoin::TXO->my_utxo()), 0,
    "genesis coins are not in the balance");
is(sum0(map { $_->value } QBitcoin::TXO->staked_utxo()), $genesis_value,
    "genesis coins are a stake source");

# --- RPC marking ---------------------------------------------------------------

my $res = rpc("listmyaddresses")->_rpc_result;
ok($res->{$gen_address}{stakeonly}, "listmyaddresses: genesis address is stakeonly");
ok($res->{$gen_address}{staked}, "listmyaddresses: genesis address is staked");

$res = rpc("getaddressinfo", $gen_address)->_rpc_result;
ok($res->{stakeonly}, "getaddressinfo: genesis address is stakeonly");
ok($res->{ismine}, "getaddressinfo: genesis address is mine");

# --- stake flag toggle re-rolls the stake-only outputs --------------------------

rpc("unstakeaddress", $gen_address);
is(scalar QBitcoin::TXO->staked_utxo(), 0,
    "unstaked genesis coins are not a stake source");
is(scalar QBitcoin::TXO->my_utxo(), 0,
    "unstaked genesis coins are still not in the balance");
is(sum0(map { $_->value } QBitcoin::Wallet::UTXO::myutxo_all()), $genesis_value,
    "unstaked genesis coins remain tracked by the wallet");

rpc("stakeaddress", $gen_address);
is(sum0(map { $_->value } QBitcoin::TXO->staked_utxo()), $genesis_value,
    "re-staked genesis coins are a stake source again");
is(scalar QBitcoin::TXO->my_utxo(), 0,
    "re-staked genesis coins are still not in the balance");

# --- a normal wallet address is unaffected --------------------------------------

my $pk2 = generate_keypair(CRYPT_ALGO_ECDSA);
my ($spend_address) = addresses_by_pubkey($pk2->pubkey_by_privkey, CRYPT_ALGO_ECDSA);
my $spend_addr = QBitcoin::MyAddress->create({
    private_key => wallet_import_format($pk2->pk_serialize),
    address     => $spend_address,
});

my $stake_tx = send_tx(-$static_reward);
undef $last_tx;
my $fund_value = 700;
my $fund_out = QBitcoin::TXO->new_txo(value => $fund_value, scripthash => scalar $spend_addr->scripthash, num => 0, data => "");
my $fund_tx = QBitcoin::Transaction->new(
    out           => [ $fund_out ],
    in            => [],
    fee           => 0,
    tx_type       => TX_TYPE_COINBASE,
    coins_created => $fund_value,
);
$fund_tx->calculate_hash;
$fund_out->tx_in = $fund_tx->hash;
send_raw_tx($fund_tx) or die "Can't send coinbase tx\n";
send_block(1, "a1", "a0", 5, $stake_tx, $fund_tx);
is(QBitcoin::Block->blockchain_height, 1, "Block a1 received");

is(sum0(map { $_->value } QBitcoin::TXO->my_utxo()), $fund_value,
    "only the spendable coins are in the balance");

blockchain_synced(1);
mempool_synced(1);
$res = rpc("getbalance")->_rpc_result;
is($res, $fund_value / DENOMINATOR, "getbalance excludes the genesis coins");

$res = rpc("getaddressinfo", $spend_address)->_rpc_result;
ok(!$res->{stakeonly}, "getaddressinfo: normal address is not stakeonly");
$res = rpc("listmyaddresses")->_rpc_result;
ok(!$res->{$spend_address}{stakeonly}, "listmyaddresses: normal address is not stakeonly");

done_testing();
