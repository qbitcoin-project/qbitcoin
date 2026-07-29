#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use Test::MockModule;
use QBitcoin::Test::ORM qw(dbh);
use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::Script::OpCodes qw(:OPCODES);
use QBitcoin::ValueUpgraded qw(upgrade_value level_by_total);
use QBitcoin::Peer;
use QBitcoin::Connection;
use QBitcoin::Coinbase;
use QBitcoin::Transaction;
use QBitcoin::Mempool;
use QBitcoin::Block;
use Bitcoin::Serialized;
use Bitcoin::Transaction;
use Bitcoin::Block;
use Bitcoin::Protocol;

#$config->{debug} = 1;
$config->{regtest} = 1;

# UPGRADE_STOP_UTXO for regtest contains the block-9 coinbase, "0437...97c9:0"
my ($stop_utxo) = values %{&UPGRADE_STOP_UTXO};
my ($stop_txid, $stop_vout) = split /:/, $stop_utxo;
ok($stop_txid, "regtest UPGRADE_STOP_UTXO is not empty");

my $peer = QBitcoin::Peer->get_or_create(type_id => PROTOCOL_BITCOIN, state => STATE_CONNECTED, ip => 'btc-test-node');
my $connection = QBitcoin::Connection->new(peer => $peer, state => STATE_CONNECTED);
my $T0 = time() - 8000;
my %BLOCKS; # in-memory blocks with transactions, for merkle_path

# real btc block hashes are 32 bytes; serialization relies on that
sub H { substr($_[0] . "\x00" x 32, 0, 32) }

my $burn_tx1 = make_burn_tx("\xAA");
my $burn_tx2 = make_burn_tx("\xBB");
my $burn_tx2c = make_burn_tx("\xCC");
my $burn_tx3 = make_burn_tx("\xEE");
# The stop-utxo spending transaction burns its own output to the lock address too:
# even this burn must not be converted (the whole spending tx is after the boundary)
my $spend_tx = make_tx(
    in  => [ [ scalar reverse(pack("H*", $stop_txid)), $stop_vout, "\x00" ] ],
    out => [ [ 50*100000000, QBT_LOCK_SCRIPT ], [ 0, OP_RETURN . pack("C", 20) . "\xDD" x 20 ] ],
);

send_block(0, H("b0"), undef, 100, []);
send_block(1, H("b1"), H("b0"),  100, [ $burn_tx1 ]);

is(QBitcoin::Coinbase->first_stop, undef, "no stop before the spend");
ok(coinbase_row($burn_tx1), "burn before the stop spend converted");

# Burn before the stop-utxo spend in the same btc block converts, the spending tx and
# everything after it does not. A peer may relay a coinbase transaction before the stop
# becomes known (between the btc block header and its scan); the stored record must be
# deleted when the stop record appears.
send_block(2, H("b2"), H("b1"), 100, [ $burn_tx2, $spend_tx, $burn_tx2c ], sub {
    QBitcoin::Coinbase->create(
        btc_block_height => 2,
        btc_tx_num       => 2,
        btc_out_num      => 0,
        btc_tx_hash      => tx_obj($burn_tx2c)->hash,
        btc_tx_data      => $burn_tx2c,
        merkle_path      => "",
        value_btc        => tx_obj($burn_tx2c)->out->[0]{value},
        scripthash       => "\xCC" x 20,
    );
    ok(coinbase_row($burn_tx2c), "relayed coinbase record stored before the stop is known");
});

my $first_stop = QBitcoin::Coinbase->first_stop;
is_deeply($first_stop, { btc_block_height => 2, btc_tx_num => 1 }, "first stop is the spending transaction position");
ok(coinbase_row($burn_tx2), "burn before the spending tx in the same block converted");
ok(!coinbase_row($spend_tx), "burn output of the spending tx itself not converted");
ok(!coinbase_row($burn_tx2c), "burn after the spending tx deleted with the stop record and not rescanned");
my ($stop_row) = QBitcoin::Coinbase->fetch(upgrade_stop => 1);
ok($stop_row, "stop-utxo spend stored in the coinbase table");
if ($stop_row) {
    is($stop_row->{btc_block_height}, 2, "stop record btc block height");
    is($stop_row->{btc_tx_num}, 1, "stop record btc tx num");
    is($stop_row->{btc_out_num}, 0, "stop record input index");
    is($stop_row->{btc_tx_hash}, tx_obj($spend_tx)->hash, "stop record spending tx");
    is($stop_row->{value}, 0, "stop record has zero value");
    ok(!defined($stop_row->{scripthash}), "stop record has no scripthash");
}

# Blocks after the stop are not scanned for coinbase at all
send_block(3, H("b3"), H("b2"), 100, [ $burn_tx3 ]);
ok(!coinbase_row($burn_tx3), "burn in the next block not converted");

# The static upgrade_stopped signal is not affected by the stop-utxo spend
ok(!Bitcoin::Block->upgrade_stopped($T0 + 10000000), "static upgrade_stopped not triggered by the spend");

# Maturity: the marker is not produced until the spending block has enough confirmations
is(QBitcoin::Coinbase->get_new_stop(time()), undef, "no marker tx until btc confirmations");
send_block($_, H("b$_"), H("b" . ($_-1)), 100, []) for 4 .. 8;

my @new_coinbase = sort { $a->btc_block_height <=> $b->btc_block_height } QBitcoin::Coinbase->get_new(time());
is_deeply([ map { $_->btc_tx_hash } @new_coinbase ],
          [ tx_obj($burn_tx1)->hash, tx_obj($burn_tx2)->hash ],
          "get_new returns both pre-stop coinbases, including the same-block one");
is($new_coinbase[0]->after_stop, 0, "pre-stop coinbase is not after the stop");
my $stop = QBitcoin::Coinbase->get_new_stop(time());
ok($stop, "mature stop record is offered for the marker tx");
is($stop && $stop->upgrade_stop, 1, "offered record is a stop record");
is($stop && $stop->value_btc, 0, "stop record carries no btc value");

# Ordering: the stop record follows the last pre-stop coinbase and precedes
# every coinbase of its own (and any later) btc transaction
my $stop_prev = $stop->prev;
is($stop_prev && $stop_prev->{btc_tx_hash}, tx_obj($burn_tx2)->hash, "stop record prev is the last pre-stop coinbase");
my $same_tx_coinbase = QBitcoin::Coinbase->new(btc_block_height => 2, btc_tx_num => 1, btc_out_num => 0, btc_tx_hash => H("x1"), upgrade_stop => 0);
my $prev = $same_tx_coinbase->prev;
ok($prev && $prev->{upgrade_stop}, "prev of a coinbase in the spending tx is the stop record");
my $later_coinbase = QBitcoin::Coinbase->new(btc_block_height => 5, btc_tx_num => 0, btc_out_num => 0, btc_tx_hash => H("x2"), upgrade_stop => 0);
$prev = $later_coinbase->prev;
ok($prev && $prev->{upgrade_stop}, "prev of a later coinbase is the stop record");
my $second_stop = QBitcoin::Coinbase->new(btc_block_height => 5, btc_tx_num => 0, btc_out_num => 0, btc_tx_hash => H("x3"), upgrade_stop => 1);
$prev = $second_stop->prev;
ok($prev && $prev->{upgrade_stop}, "prev of a second stop is the first stop record");

# A post-stop record may return to the unconfirmed state (reorg of a branch confirmed
# before the stop became known); get_new must never offer it to the producer.
# The pre-stop coinbases are skipped by the in-memory cache here, so the empty result
# proves the post-stop record is filtered out.
QBitcoin::Coinbase->create(
    btc_block_height => 3,
    btc_tx_num       => 0,
    btc_out_num      => 0,
    btc_tx_hash      => tx_obj($burn_tx3)->hash,
    btc_tx_data      => $burn_tx3,
    merkle_path      => "",
    value_btc        => tx_obj($burn_tx3)->out->[0]{value},
    scripthash       => "\xEE" x 20,
);
is_deeply([ QBitcoin::Coinbase->get_new(time()+1) ], [], "get_new never offers the post-stop record");
my ($post_stop_row) = QBitcoin::Coinbase->find(btc_tx_hash => tx_obj($burn_tx3)->hash, upgrade_stop => 0);
is($post_stop_row && $post_stop_row->after_stop, 1, "post-stop coinbase record is after the stop");

# Build the marker transaction and check the serialization roundtrip
my $coinbase_tx1 = QBitcoin::Transaction->new_coinbase($new_coinbase[0], 0);
my $coinbase_tx2 = QBitcoin::Transaction->new_coinbase($new_coinbase[1], 0);
my $marker_tx = QBitcoin::Transaction->new_upgrade_stop($stop);
ok($marker_tx, "marker transaction built");
ok($marker_tx->is_upgrade_stop, "marker tx type");
is($marker_tx->fee, 0, "marker tx has no fee");
is($marker_tx->coins_created, 0, "marker tx creates no coins");
is(scalar @{$marker_tx->in}, 0, "marker tx has no inputs");
is(scalar @{$marker_tx->out}, 0, "marker tx has no outputs");
ok(defined($marker_tx->min_tx_time), "marker tx has confirmation time bound");

my $serialized = $marker_tx->serialize;
my $restored = QBitcoin::Transaction->deserialize(Bitcoin::Serialized->new($serialized));
ok($restored, "marker tx deserialized");
is($restored && $restored->hash, $marker_tx->hash, "marker tx hash roundtrip");
ok($restored && $restored->is_upgrade_stop, "deserialized marker tx type");
ok($restored && $restored->up && $restored->up->upgrade_stop, "deserialized marker payload is a stop record");
is($restored && $restored->validate, 0, "marker tx is valid");

# A forged marker whose btc tx does not spend a listed utxo must not deserialize
my $forged = pack("c", TX_TYPE_UPGRADE_STOP) . "\x00" . "\x00"
    . varint(1) . H("b1") . varint(0) . varint(0) . varstr($burn_tx1) . varstr("");
ok(!QBitcoin::Transaction->deserialize(Bitcoin::Serialized->new($forged)), "marker with non-stop spend rejected");

# Marker weight equals the coinbase weight of the whole remaining quota
my $upgraded = tx_obj($burn_tx1)->out->[0]{value} + tx_obj($burn_tx2)->out->[0]{value};
my $weight = $marker_tx->upgrade_stop_weight($T0 + 100, $upgraded);
ok($weight > 0, "marker weight is positive");
my $expect = upgrade_value(UPGRADE_MAX_VALUE - $upgraded, level_by_total($upgraded));
my $confirm_time = $stop->btc_confirm_time;
my $base = timeslot($confirm_time);
my $virt = timeslot($confirm_time - COINBASE_WEIGHT_TIME);
my $expect_weight = int($expect / 0x10000 * ($base - $virt) / BLOCK_INTERVAL * ($base - $virt) / (timeslot($T0 + 100) - $virt));
is($weight, $expect_weight, "marker weight formula");
is($marker_tx->upgrade_stop_weight($T0 + 100, UPGRADE_MAX_VALUE), 0, "marker weight is zero when quota exhausted");

# Mempool ordering and filters. An adversarial coinbase for the burn output of the
# spending tx itself must be dropped by its btc position.
my $evil_up = QBitcoin::Coinbase->new(
    btc_block_height => 2,
    btc_tx_num       => 1,
    btc_out_num      => 0,
    btc_tx_hash      => tx_obj($spend_tx)->hash,
    btc_tx_data      => $spend_tx,
    merkle_path      => $BLOCKS{H("b2")}->merkle_path(1),
    value_btc        => tx_obj($spend_tx)->out->[0]{value},
    scripthash       => "\xDD" x 20,
    upgrade_stop     => 0,
);
my $evil_tx = QBitcoin::Transaction->new_coinbase($evil_up, 0);
my $prev_block = QBitcoin::Block->new(height => 0, upgraded => 0, upgrade_stopped => 0, weight => 0, time => $T0, min_fee => 0, size => 0);
my @chosen = QBitcoin::Mempool->choose_for_block(0, time(), $prev_block, 1, 0);
is_deeply([ map { $_->hash } grep { $_->is_coinbase || $_->is_upgrade_stop } @chosen ],
          [ $coinbase_tx1->hash, $coinbase_tx2->hash, $marker_tx->hash ],
          "mempool orders coinbases before the marker and drops the post-stop coinbase");
my $stopped_block = QBitcoin::Block->new(height => 0, upgraded => 0, upgrade_stopped => 1, weight => 0, time => $T0, min_fee => 0, size => 0);
@chosen = QBitcoin::Mempool->choose_for_block(0, time(), $stopped_block, 1, 0);
is_deeply([ grep { $_->is_coinbase || $_->is_upgrade_stop } @chosen ], [],
          "no coinbase and no second marker after the stop in the branch");

# upgrade_stopped is a derived block attribute: for blocks loaded from the database it
# comes from the height of the stored (confirmed) marker transaction
is(QBitcoin::Block->new(height => 100)->upgrade_stopped, 0, "no upgrade_stopped without a stored marker");
dbh->do("INSERT INTO `block` (height, time, hash, size, weight, merkle_root) VALUES (7, ?, ?, 0, 0, ?)",
    undef, $T0, H("qb7"), H("mr"));
dbh->do("INSERT INTO `transaction` (id, hash, block_height, block_pos, tx_type, size, fee) VALUES (999, ?, 7, 1, ?, ?, 0)",
    undef, $marker_tx->hash, TX_TYPE_UPGRADE_STOP, $marker_tx->size);
dbh->do("UPDATE `coinbase` SET tx_out = 999 WHERE upgrade_stop = 1");
QBitcoin::Coinbase->reset_stop_confirmed;
is(QBitcoin::Coinbase->stop_confirmed_height, 7, "stop confirmed height from the stored marker tx");
is(QBitcoin::Block->new(height => 7)->upgrade_stopped, 1, "upgrade_stopped derived for the marker block and above");
is(QBitcoin::Block->new(height => 6)->upgrade_stopped, 0, "upgrade_stopped not derived below the marker block");
dbh->do("UPDATE `coinbase` SET tx_out = NULL WHERE upgrade_stop = 1");
dbh->do("DELETE FROM `transaction` WHERE id = 999");
dbh->do("DELETE FROM `block` WHERE height = 7");
QBitcoin::Coinbase->reset_stop_confirmed;

# The scan gate includes the block with the spend (exclusive bound is the next height),
# and keeps scanning while there are pending downgrades: their btc payments may arrive
# after the stop-utxo spend
is(Bitcoin::Protocol::btc_scan_height(), 3, "btc scan bound is the height after the spend");
{
    my $spv_module = Test::MockModule->new('QBitcoin::Downgrade::Spv');
    $spv_module->mock('pending_txids', sub { { "fake_btc_txid" => 1 } });
    is(Bitcoin::Protocol::btc_scan_height(), UPGRADE_MAX_BLOCKS, "btc scan continues for pending downgrade payments");
}

# btc reorg reverting the spending block deletes the stop records and resumes the conversion
send_block(undef, H("c$_"), $_ == 2 ? H("b1") : H("c" . ($_-1)), 110, []) for 2 .. 10;
my ($b2) = Bitcoin::Block->find(hash => H("b2"));
is($b2->height, undef, "spending block reverted from the main chain");
is(QBitcoin::Coinbase->first_stop, undef, "stop position reset after the revert");
is(Bitcoin::Protocol::btc_scan_height(), UPGRADE_MAX_BLOCKS, "conversion scan resumed after the revert");

done_testing();

sub make_tx {
    my (%arg) = @_;
    my $data = pack("V", 1);
    $data .= varint(scalar @{$arg{in}});
    foreach my $in (@{$arg{in}}) {
        $data .= $in->[0] . pack("V", $in->[1]) . varstr($in->[2]) . "\xff\xff\xff\xff";
    }
    $data .= varint(scalar @{$arg{out}});
    foreach my $out (@{$arg{out}}) {
        $data .= pack("Q<", $out->[0]) . varstr($out->[1]);
    }
    $data .= pack("V", 0);
    return $data;
}

# Burn (upgrade) transaction: output to the burn address plus OP_RETURN with the destination scripthash
sub make_burn_tx {
    my ($fill) = @_;
    return make_tx(
        in  => [ [ $fill x 32, 0, "\x00" ] ],
        out => [ [ 100000000, QBT_LOCK_SCRIPT ], [ 0, OP_RETURN . pack("C", 20) . $fill x 20 ] ],
    );
}

sub tx_obj {
    my ($tx_data) = @_;
    return Bitcoin::Transaction->deserialize(Bitcoin::Serialized->new($tx_data));
}

sub send_block {
    my ($time_num, $hash, $prev_hash, $weight, $txs, $before_scan) = @_;
    my @tx_objects = map { tx_obj($_) } @$txs;
    my $block = Bitcoin::Block->new(
        hash        => $hash,
        prev_hash   => $prev_hash // ZERO_HASH,
        bits        => int((29 << 24) + 0xffff / $weight + 0.5),
        time        => $T0 + ($time_num // 500)*10,
        nonce       => 0,
        version     => 2,
        scanned     => 0,
        merkle_root => ZERO_HASH,
        transactions => \@tx_objects,
    );
    $block->merkle_root = $block->calculate_merkle_root if @tx_objects;
    $BLOCKS{$hash} = $block;
    $connection->protocol->process_btc_block($block)
        or return;
    $block->create();
    $before_scan->() if $before_scan;
    # same gate as in Bitcoin::Protocol::cmd_block
    if (@tx_objects && $block->height && $block->height < Bitcoin::Protocol::btc_scan_height()) {
        my $tx_data = Bitcoin::Serialized->new(varint(scalar @$txs) . join("", @$txs));
        !defined($connection->protocol->process_transactions($block, $tx_data))
            or die "process_transactions failed for block $hash\n";
    }
}

sub coinbase_row {
    my ($tx_data) = @_;
    return QBitcoin::Coinbase->fetch(btc_tx_hash => tx_obj($tx_data)->hash, btc_out_num => 0, upgrade_stop => 0) ? 1 : 0;
}
