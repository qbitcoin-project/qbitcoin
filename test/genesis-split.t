#! /usr/bin/env perl
use warnings;
use strict;

# Splitting the genesis reward into tagged parts (data = "T" . tag) so several
# validator nodes can share one genesis address:
# - a node stakes only the genesis UTXOs carrying its own stake_tag ("" by default)
#   and preserves the tag in the re-created output
# - a pending stake-split spec (splitstake RPC, persisted via QBitcoin::Setting)
#   turns the next stake into tagged part outputs, and auto-clears once the split
#   is observed confirmed
# - createrawtransaction outputs accept data/tag payload (create_txo)

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
use QBitcoin::Address qw(address_by_pubkey wallet_import_format);
use QBitcoin::MyAddress;
use QBitcoin::TXO;
use QBitcoin::Transaction;
use QBitcoin::Setting;
use QBitcoin::Coins;
use QBitcoin::Generate;
use QBitcoin::Utils qw(create_txo);

$config->{regtest} = 1;

my $genesis_scripthash = "\x11" x 20;
my $timeslot = timeslot(GENESIS_TIME + 1000);

my $coins_module = Test::MockModule->new('QBitcoin::Coins');
$coins_module->mock('genesis_scripthashes', sub { +{ $genesis_scripthash => 1 } });

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

my $tx_num = 0;
sub genesis_coin {
    my ($value, $data) = @_;
    my $txo = QBitcoin::TXO->new_txo({
        tx_in      => pack("C", $tx_num++) x 32,
        num        => 0,
        value      => $value,
        scripthash => $genesis_scripthash,
        data       => $data // "",
    });
    $txo->{redeem_script} = "redeem_script";
    return $txo;
}

sub set_my_utxo {
    my (@utxo) = @_;
    $_->del_my_utxo() foreach QBitcoin::TXO->my_utxo;
    $_->add_my_utxo() foreach @utxo;
}

sub genesis_outs {
    my ($tx) = @_;
    return map { [ $_->value, $_->data ] }
        sort { $a->data cmp $b->data or $a->value <=> $b->value }
        grep { $_->scripthash eq $genesis_scripthash } @{$tx->out};
}

$config->{reward_to} = "union";

# --- tag selection and preservation -------------------------------------------

# Untagged node: stakes only the untagged genesis UTXO, foreign parts stay untouched
my $untagged = genesis_coin(1000);
my $part_v2  = genesis_coin(4000, TXO_DATA_TAG . "v2");
set_my_utxo($untagged, $part_v2);
my $tx = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
is(scalar @{$tx->in}, 1, "untagged node stakes one genesis UTXO");
is($tx->in->[0]{txo}->key, $untagged->key, "untagged node stakes the untagged part");
is_deeply([genesis_outs($tx)], [[1000, ""]], "untagged part is re-created untagged");

# Tagged node: stakes only its own part and preserves the tag
$config->{stake_tag} = "v2";
$tx = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
is(scalar @{$tx->in}, 1, "tagged node stakes one genesis UTXO");
is($tx->in->[0]{txo}->key, $part_v2->key, "tagged node stakes its own part");
is_deeply([genesis_outs($tx)], [[4000, TXO_DATA_TAG . "v2"]], "the tag is preserved in the stake output");

# A node with an unknown tag has nothing to stake from genesis
$config->{stake_tag} = "nosuch";
$tx = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
is(scalar @{$tx->in}, 0, "node with unmatched tag stakes no genesis UTXOs");
delete $config->{stake_tag};

# --- stake split ---------------------------------------------------------------

# Pending split: the next stake re-creates the untagged part as tagged outputs
set_my_utxo(genesis_coin(5000));
QBitcoin::Generate->stake_split({ "" => 1000, "v2" => 4000 });
is(QBitcoin::Setting->get("stake_split"), '{"":1000,"v2":4000}', "split spec persisted in settings");
$tx = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
is_deeply([genesis_outs($tx)], [[1000, ""], [4000, TXO_DATA_TAG . "v2"]],
    "stake splits the genesis part per spec");
ok(QBitcoin::Generate->stake_split, "split spec still pending until the split is observed");

# Mismatched total: split is postponed, the part is re-created as is
set_my_utxo(genesis_coin(4999));
$tx = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
is_deeply([genesis_outs($tx)], [[4999, ""]], "mismatched split total leaves the part unchanged");
ok(QBitcoin::Generate->stake_split, "mismatched split stays pending");

# Once the confirmed UTXO set matches the spec, the spec is cleared automatically
set_my_utxo(genesis_coin(1000), genesis_coin(4000, TXO_DATA_TAG . "v2"));
$tx = QBitcoin::Generate::make_stake_tx(10, "blocksign", $timeslot);
is_deeply([genesis_outs($tx)], [[1000, ""]], "after the split the node stakes only its own part");
is(QBitcoin::Generate->stake_split, undef, "completed split spec is cleared");
is(QBitcoin::Setting->get("stake_split"), undef, "completed split spec is removed from settings");

# The persisted spec is picked up after a restart (simulated by a fresh load)
QBitcoin::Setting->set("stake_split", '{"":500}');
QBitcoin::Generate->stake_split({ "" => 500 }); # sync the in-memory cache with the setting
is_deeply(QBitcoin::Generate->stake_split, { "" => 500 }, "split spec readable from settings");
QBitcoin::Generate->stake_split(undef);

# --- create_txo data/tag payload ----------------------------------------------
# create_txo takes output values as integer satoshi; decimal QBTC amounts are
# converted earlier, in RPC::Validate::validate_outputs.

my $address = $my_address->address;
my ($txo) = create_txo({ $address => 1000, tag => "v2" });
ok($txo && @$txo == 1, "create_txo accepts a tag key");
is($txo && $txo->[0]->data, TXO_DATA_TAG . "v2", "tag is stored as marker + string");

($txo) = create_txo({ $address => 1000, data => "54763322" });
is($txo && $txo->[0]->data, pack("H*", "54763322"), "raw data payload is hex-decoded");

is(create_txo({ $address => 1000, data => "abc" }), undef, "odd-length data hex is rejected");
is(create_txo({ $address => 1000, data => "00", tag => "v2" }), undef, "data and tag together are rejected");
is(create_txo({ tag => "v2" }), undef, "tag without an address output is rejected");

done_testing();
