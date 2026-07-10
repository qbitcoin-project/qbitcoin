#! /usr/bin/env perl
use warnings;
use strict;

# Genesis-reward coins are service coins for the initial validation weight: consensus
# forbids any transaction from decreasing the balance of the genesis-reward scripthash
# (QBitcoin::Transaction::check_genesis_balance). This covers:
# - discovery of the genesis scripthash from the in-core genesis block
# - the balance rule for standard and stake transactions
# - stake generation returning the genesis value to the same scripthash
# - slashing exempting genesis UTXOs (and rejecting a slash that spends one)

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use Test::MockModule;
use List::Util qw(sum0);
use QBitcoin::Test::ORM;
use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::Crypto qw(hash160 generate_keypair);
use QBitcoin::Script::OpCodes qw(:OPCODES);
use QBitcoin::Script qw(op_pushdata);
use QBitcoin::Address qw(address_by_pubkey wallet_import_format);
use QBitcoin::MyAddress;
use QBitcoin::TXO;
use QBitcoin::Transaction;
use QBitcoin::Block;
use QBitcoin::Slashing;
use QBitcoin::Coins;
use QBitcoin::Generate;

$config->{regtest} = 1;
$config->{genesis_reward} = 5000;

my $GENESIS_VALUE = 5000;

# anyone-can-spend scripts: no signature needed, keeps the test key-free
my $genesis_script     = op_pushdata(pack("v", 1)) . OP_DROP . OP_1;
my $genesis_scripthash = hash160($genesis_script);
my $other_script       = op_pushdata(pack("v", 2)) . OP_DROP . OP_1;
my $other_scripthash   = hash160($other_script);

my $timeslot = timeslot(GENESIS_TIME + 1000);

sub make_coin {
    my ($txid, $num, $value, $script) = @_;
    my $txo = QBitcoin::TXO->new_txo({
        tx_in      => $txid,
        num        => $num,
        value      => $value,
        scripthash => hash160($script),
        data       => "",
    });
    $txo->set_redeem_script($script) == 0 or die "set_redeem_script failed\n";
    return $txo;
}

sub out_txo {
    my ($value, $scripthash) = @_;
    return QBitcoin::TXO->new_txo({ value => $value, scripthash => $scripthash, data => "" });
}

# --- genesis scripthash discovery from the in-core genesis block -------------

my $genesis_stake = QBitcoin::Transaction->new(
    in      => [],
    out     => [ out_txo($GENESIS_VALUE, $genesis_scripthash) ],
    fee     => -$GENESIS_VALUE,
    tx_type => TX_TYPE_STAKE,
);
my $genesis_block = QBitcoin::Block->new({
    height       => 0,
    time         => GENESIS_TIME,
    transactions => [ $genesis_stake ],
});
my $block_module = Test::MockModule->new('QBitcoin::Block');
$block_module->mock('best_block', sub { $_[1] == 0 ? $genesis_block : undef });

# The result is cached inside QBitcoin::Coins, so the mock is only needed here
is_deeply(QBitcoin::Coins->genesis_scripthashes, { $genesis_scripthash => 1 },
    "genesis scripthash discovered from the genesis block stake tx");
$block_module->unmock('best_block');

# --- balance rule for standard transactions ----------------------------------

# Full script checks need the input source transactions; the genesis balance rule
# runs before them in validate(), so mock them out for the standard-tx cases.
my $script_module = Test::MockModule->new('QBitcoin::Transaction');
$script_module->mock('check_input_script', sub { 0 });

my $tx_num = 0;
sub make_standard_tx {
    my ($in, $out, $fee) = @_;
    my $num = 0;
    $_->{num} = $num++ foreach @$out;
    my $tx = QBitcoin::Transaction->new(
        in      => [ map +{ txo => $_, siglist => [] }, @$in ],
        out     => $out,
        fee     => $fee,
        tx_type => TX_TYPE_STANDARD,
    );
    $tx->calculate_hash;
    return $tx;
}

sub genesis_coin {
    my ($value) = @_;
    return make_coin(pack("C", $tx_num++) x 32, 0, $value // $GENESIS_VALUE, $genesis_script);
}
sub other_coin {
    my ($value) = @_;
    return make_coin(pack("C", $tx_num++) x 32, 0, $value, $other_script);
}

my $tx_keep = make_standard_tx(
    [ genesis_coin(), other_coin(1000) ],
    [ out_txo($GENESIS_VALUE, $genesis_scripthash), out_txo(900, $other_scripthash) ],
    100,
);
is($tx_keep->validate, 0, "spending genesis coins with full value returned is valid");

my $tx_split = make_standard_tx(
    [ genesis_coin(), other_coin(1000) ],
    [ out_txo(2500, $genesis_scripthash), out_txo(2500, $genesis_scripthash), out_txo(900, $other_scripthash) ],
    100,
);
is($tx_split->validate, 0, "splitting genesis coins across outputs to the same scripthash is valid");

my $tx_steal = make_standard_tx(
    [ genesis_coin(), other_coin(1000) ],
    [ out_txo($GENESIS_VALUE - 1000, $genesis_scripthash), out_txo(1900, $other_scripthash) ],
    100,
);
isnt($tx_steal->validate, 0, "decreasing genesis balance is rejected");

my $tx_fee = make_standard_tx(
    [ genesis_coin() ],
    [ out_txo($GENESIS_VALUE - 100, $genesis_scripthash) ],
    100,
);
isnt($tx_fee->validate, 0, "paying the fee from genesis coins is rejected");

my $tx_donate = make_standard_tx(
    [ other_coin(1000) ],
    [ out_txo(500, $genesis_scripthash), out_txo(400, $other_scripthash) ],
    100,
);
is($tx_donate->validate, 0, "increasing genesis balance is valid");

my $tx_plain = make_standard_tx(
    [ other_coin(1000) ],
    [ out_txo(900, $other_scripthash) ],
    100,
);
is($tx_plain->validate, 0, "transaction not touching genesis coins is unaffected");

# --- balance rule for stake transactions --------------------------------------

sub make_stake {
    my ($coins, $out, $prev, $digest, $slot) = @_;
    $slot //= $timeslot;
    my $stake = QBitcoin::Transaction->new(
        in              => [ map +{ txo => $_, siglist => [] }, @$coins ],
        out             => $out,
        fee             => -10,
        tx_type         => TX_TYPE_STAKE,
        block_sign_data => ($prev // "\x11" x 32) . pack("N", $slot) . ($digest // "\xa1" x 32),
    );
    $stake->calculate_hash;
    return $stake;
}

my $stake_ok = make_stake(
    [ genesis_coin() ],
    [ out_txo($GENESIS_VALUE + 10, $genesis_scripthash) ],
);
is($stake_ok->validate, 0, "stake returning genesis value (plus reward) to the same scripthash is valid");

my $stake_bad = make_stake(
    [ genesis_coin() ],
    [ out_txo($GENESIS_VALUE + 10, $other_scripthash) ],
);
isnt($stake_bad->validate, 0, "stake moving genesis value to another scripthash is rejected");

$script_module->unmock_all();

# --- stake generation keeps genesis value on its scripthash -------------------

my $my_address;
my $generate_module = Test::MockModule->new('QBitcoin::Generate');
$generate_module->mock('stake_address', sub { $my_address });
$generate_module->mock('txo_confirmed', sub { 1 });
my $txo_module = Test::MockModule->new('QBitcoin::TXO');
$txo_module->mock('my_roles', sub { QBitcoin::Wallet::UTXO::UTXO_STAKED });
my $transaction_module = Test::MockModule->new('QBitcoin::Transaction');
$transaction_module->mock('txo_time', sub { $timeslot - 100 });
$transaction_module->mock('sign_transaction',
    sub {
        foreach my $in (@{$_[0]->in}) {
            $in->{siglist} = [];
        }
    }
);

my $pk = generate_keypair(CRYPT_ALGO_ECDSA);
$my_address = QBitcoin::MyAddress->new(
    private_key => wallet_import_format($pk->pk_serialize),
    address     => address_by_pubkey($pk->pubkey_by_privkey, CRYPT_ALGO_ECDSA),
    staked      => 1,
);

sub set_my_utxo {
    my (@utxo) = @_;
    $_->del_my_utxo() foreach QBitcoin::TXO->my_utxo;
    $_->add_my_utxo() foreach @utxo;
}

foreach my $reward_to (qw(join union separate)) {
    $config->{reward_to} = $reward_to;
    set_my_utxo(genesis_coin(), other_coin(1000));
    my $tx = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
    is(scalar @{$tx->in}, 2, "stake tx in $reward_to mode spends both UTXOs");
    my ($genesis_out) = grep { $_->scripthash eq $genesis_scripthash } @{$tx->out};
    ok($genesis_out, "stake tx in $reward_to mode has a genesis output");
    is($genesis_out && $genesis_out->value, $GENESIS_VALUE,
        "genesis value is returned unchanged in $reward_to mode");
    is($tx->check_genesis_balance, 0, "generated stake tx keeps the genesis balance in $reward_to mode");
}

# genesis coins are the only stake (typical chain start)
$config->{reward_to} = "union";
set_my_utxo(genesis_coin());
my $tx_genesis_only = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
is(scalar @{$tx_genesis_only->in}, 1, "genesis-only stake tx spends the genesis UTXO");
my ($gen_out) = grep { $_->scripthash eq $genesis_scripthash } @{$tx_genesis_only->out};
is($gen_out && $gen_out->value, $GENESIS_VALUE, "genesis-only stake tx returns the full genesis value");
is($tx_genesis_only->check_genesis_balance, 0, "genesis-only stake tx keeps the genesis balance");

# --- the reward destination must not be a genesis address ---------------------

# A wallet address (not a bare scripthash) is needed here, because the reward
# destination is picked from stake_address(); mark its scripthash as the genesis one.
my $gen_pk = generate_keypair(CRYPT_ALGO_ECDSA);
my $genesis_address = QBitcoin::MyAddress->new(
    private_key => wallet_import_format($gen_pk->pk_serialize),
    address     => address_by_pubkey($gen_pk->pubkey_by_privkey, CRYPT_ALGO_ECDSA),
    staked      => 1,
);
my $gen_addr_sh = $genesis_address->scripthash;
my $my_addr_sh  = $my_address->scripthash;

my $genesis_addr_module = Test::MockModule->new('QBitcoin::Coins');
$genesis_addr_module->mock('genesis_scripthashes', sub { +{ $gen_addr_sh => 1 } });
# The genesis address comes first: without filtering it would be picked as the reward destination
$generate_module->mock('stake_address', sub { ($genesis_address, $my_address) });

sub addr_coin {
    my ($value, $scripthash) = @_;
    my $txo = QBitcoin::TXO->new_txo({
        tx_in      => pack("C", $tx_num++) x 32,
        num        => 0,
        value      => $value,
        scripthash => $scripthash,
        data       => "",
    });
    $txo->{redeem_script} = "redeem_script";
    return $txo;
}

sub outs_by_sh {
    my ($tx, $scripthash) = @_;
    return grep { $_->scripthash eq $scripthash } @{$tx->out};
}

# join with other coins: the joined coins and the reward skip the genesis address
$config->{reward_to} = "join";
set_my_utxo(addr_coin($GENESIS_VALUE, $gen_addr_sh), addr_coin(1000, "\x77" x 20));
my $tx_j = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
my ($j_gen) = outs_by_sh($tx_j, $gen_addr_sh);
my ($j_my)  = outs_by_sh($tx_j, $my_addr_sh);
is($j_gen && $j_gen->value, $GENESIS_VALUE, "join: genesis value returned unchanged");
is($j_my && $j_my->value, 1010, "join: joined coins and reward go to the non-genesis address");

# join / separate (falls back to join) / union with genesis-only coins:
# the reward goes to the non-genesis wallet address
foreach my $reward_to (qw(join separate union)) {
    $config->{reward_to} = $reward_to;
    set_my_utxo(addr_coin($GENESIS_VALUE, $gen_addr_sh));
    my $tx = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
    my ($gen)    = outs_by_sh($tx, $gen_addr_sh);
    my ($reward) = outs_by_sh($tx, $my_addr_sh);
    is($gen && $gen->value, $GENESIS_VALUE, "$reward_to genesis-only: genesis value returned unchanged");
    is($reward && $reward->value, 10, "$reward_to genesis-only: reward goes to the non-genesis address");
}

# wallet has only the genesis address: locking the reward there is the last resort
$generate_module->mock('stake_address', sub { ($genesis_address) });
$config->{reward_to} = "join";
set_my_utxo(addr_coin($GENESIS_VALUE, $gen_addr_sh));
my $tx_lock = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
is(sum0(map { $_->value } outs_by_sh($tx_lock, $gen_addr_sh)), $GENESIS_VALUE + 10,
    "genesis-only wallet: the reward is locked on the genesis address as a last resort");
is($tx_lock->check_genesis_balance, 0, "genesis-only wallet: the stake tx keeps the genesis balance");

# with reward_addr the reward always goes there
$generate_module->mock('stake_address', sub { ($genesis_address, $my_address) });
$generate_module->mock('reward_conf', sub { [ "\x99" x 20, 1 ] });
foreach my $reward_to (qw(join separate union)) {
    $config->{reward_to} = $reward_to;
    set_my_utxo(addr_coin($GENESIS_VALUE, $gen_addr_sh), addr_coin(1000, "\x77" x 20));
    my $tx = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
    my ($gen)    = outs_by_sh($tx, $gen_addr_sh);
    my ($reward) = outs_by_sh($tx, "\x99" x 20);
    is($gen && $gen->value, $GENESIS_VALUE, "$reward_to with reward_addr: genesis value returned unchanged");
    is($reward && $reward->value, 10, "$reward_to with reward_addr: reward goes to reward_addr");
}
$generate_module->mock('reward_conf', sub { undef });
$generate_module->mock('stake_address', sub { $my_address });
$genesis_addr_module->unmock_all();

set_my_utxo();
$transaction_module->unmock_all();

# --- slashing exempts genesis UTXOs -------------------------------------------

# Equivocation with a mixed stake: only the non-genesis UTXO is slashed
my $gen_coin  = genesis_coin();
my $norm_coin = other_coin(2000);
my $stake1 = make_stake([ $gen_coin, $norm_coin ], [ out_txo($GENESIS_VALUE + 2010, $other_scripthash) ], "\x11" x 32, "\xa1" x 32);
my $stake2 = make_stake([ $gen_coin, $norm_coin ], [ out_txo($GENESIS_VALUE + 2010, $other_scripthash) ], "\x22" x 32, "\xb2" x 32);
my $slash = QBitcoin::Slashing->new_tx($stake1, $stake2);
ok($slash, "slashing tx built for a mixed genesis/normal equivocation");
is(scalar @{$slash->in}, 1, "only the non-genesis UTXO is slashed");
is($slash->in->[0]{txo}->key, $norm_coin->key, "the slashed UTXO is the normal one");
is($slash->validate, 0, "slashing tx omitting the genesis UTXO validates");

# Equivocation with genesis-only stakes: nothing slashable
my $stake3 = make_stake([ genesis_coin() ], [ out_txo($GENESIS_VALUE + 10, $genesis_scripthash) ], "\x11" x 32, "\xa1" x 32);
my $stake4 = make_stake([ $stake3->in->[0]{txo} ], [ out_txo($GENESIS_VALUE + 10, $genesis_scripthash) ], "\x22" x 32, "\xb2" x 32);
is(QBitcoin::Slashing->new_tx($stake3, $stake4), undef, "no slashing tx when only genesis UTXOs equivocate");

# A slashing tx that does spend a genesis UTXO must be rejected: build it with the
# genesis exemption disabled, then validate against the real genesis set
my $coins_module = Test::MockModule->new('QBitcoin::Coins');
$coins_module->mock('genesis_scripthashes', sub { {} });
my $slash_bad = QBitcoin::Slashing->new_tx($stake1, $stake2);
is(scalar @{$slash_bad->in}, 2, "with exemption disabled the slashing tx spends both UTXOs");
$coins_module->unmock_all();
isnt($slash_bad->validate, 0, "slashing tx spending a genesis UTXO is rejected");

# --- total supply excludes the genesis reward ---------------------------------

my $height_module = Test::MockModule->new('QBitcoin::Block');
$height_module->mock('blockchain_height', sub { 0 });
is(QBitcoin::Coins->total, 0, "genesis reward is not counted in the total supply");
$height_module->unmock_all();

done_testing();
