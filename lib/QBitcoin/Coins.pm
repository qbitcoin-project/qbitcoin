package QBitcoin::Coins;
use warnings;
use strict;

# Running total of the generated (emitted) coins for the best blockchain branch.
# emission = sum(coinbase up_value) + sum(static block reward)
# Neither the dynamic block reward nor transaction fees are counted separately: they
# recirculate already existing coins through the reward fund and do not create emission.
# GENESIS_REWARD is not counted either: the genesis-reward coins are service coins for
# the initial validation weight, their balance can never decrease (see
# QBitcoin::Transaction::check_genesis_balance), so they never enter circulation.
#
# The total is computed once on the node startup (the only place where we scan the
# coinbase table) and then maintained incrementally on confirm/unconfirm of coinbase
# and stake transactions, so getblockchaininfo does not run a heavy query on each call
# and the value stays accurate for blocks which are still in memory (not yet stored).

use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::Log;
use QBitcoin::Config;
use QBitcoin::ORM qw(dbh);
use QBitcoin::Coinbase;
use QBitcoin::TXO;
use QBitcoin::RedeemScript;
use Bitcoin::Block;

my $UPGRADE_TOTAL = 0; # sum of up_value of all coinbase transactions in the best branch
my $STATIC_TOTAL  = 0; # sum of static block rewards in the best branch
my $INITIALIZED;

# Compute the base totals from the database. On startup the best block always equals
# max_db_height, so the persisted coinbase rows cover the whole best branch.
sub init {
    my $class = shift;
    return if $INITIALIZED;
    my ($sum) = dbh->selectrow_array("SELECT SUM(value) FROM `" . QBitcoin::Coinbase->TABLE . "` WHERE tx_out IS NOT NULL");
    $UPGRADE_TOTAL = ($sum // 0) + 0;
    my $tip;
    if (defined(my $height = QBitcoin::Block->blockchain_height)) {
        $tip = QBitcoin::Block->best_block($height);
    }
    $STATIC_TOTAL = _static_total($tip);
    $INITIALIZED = 1;
    Debugf("Coins accounting initialized: upgraded %lu, static %lu", $UPGRADE_TOTAL, $STATIC_TOTAL);
    return;
}

# Total emitted coins in satoshi (raw value, callers divide by DENOMINATOR if needed).
# The genesis reward is excluded: those coins can never be spent, only staked.
sub total {
    my $class = shift;
    return 0 unless defined QBitcoin::Block->blockchain_height;
    return $UPGRADE_TOTAL + $STATIC_TOTAL;
}

# Scripthashes holding the genesis reward: the outputs of the genesis block's
# inputless stake transaction. These are service coins - they provide a non-zero
# validation weight at the chain start but are not backed by upgraded BTC, so
# consensus forbids decreasing their balance (QBitcoin::Transaction::check_genesis_balance).
# Returns a hashref { scripthash => 1 } (empty if no genesis reward is configured),
# or undef if the genesis block is not known yet (the result is cached only once known).
my $GENESIS_SCRIPTHASHES;
sub genesis_scripthashes {
    my $class = shift;
    return $GENESIS_SCRIPTHASHES if defined $GENESIS_SCRIPTHASHES;
    my $genesis_reward = $config->{regtest} ? $config->{genesis_reward} // 0 : GENESIS_REWARD;
    return $GENESIS_SCRIPTHASHES = {} unless $genesis_reward;
    my %scripthash;
    if (my $block = QBitcoin::Block->best_block(0)) {
        # Genesis block is still in-core (fresh chain, possibly not stored yet)
        my $tx = $block->transactions->[0];
        $tx && $tx->is_stake && !@{$tx->in}
            or return undef;
        $scripthash{$_->scripthash} = 1 foreach grep { $_->value > 0 } @{$tx->out};
    }
    else {
        # QBitcoin::Transaction is always loaded by the time any transaction is
        # validated; not use'd here to avoid a compile-time dependency loop.
        my ($tx_row) = QBitcoin::Transaction->fetch(block_height => 0, block_pos => 0)
            or return undef;
        $tx_row->{tx_type} == TX_TYPE_STAKE
            or return undef;
        my $sql = "SELECT s.hash FROM `" . QBitcoin::TXO->TABLE . "` t" .
            " JOIN `" . QBitcoin::RedeemScript->TABLE . "` s ON (t.scripthash = s.id)" .
            " WHERE t.tx_in = ? AND t.value > 0";
        my $hashes = dbh->selectcol_arrayref($sql, undef, $tx_row->{id});
        $scripthash{$_} = 1 foreach @$hashes;
    }
    %scripthash
        or return undef;
    return $GENESIS_SCRIPTHASHES = \%scripthash;
}

# Prime the genesis-scripthash cache directly from the genesis stake transaction,
# called when it is confirmed. At that moment the genesis block is not yet
# installed in the best branch (Block::Receive sets best_block after validate_chain
# confirms the transactions), so the genesis_scripthashes lookup above cannot see
# it - and its outputs are entering the wallet-utxo registry right now, so their
# stake-only roles must already be decidable.
sub set_genesis_tx {
    my ($class, $tx) = @_;
    return if defined $GENESIS_SCRIPTHASHES;
    my $genesis_reward = $config->{regtest} ? $config->{genesis_reward} // 0 : GENESIS_REWARD;
    if (!$genesis_reward) {
        $GENESIS_SCRIPTHASHES = {};
        return;
    }
    $tx->is_stake && !@{$tx->in}
        or return;
    my %scripthash;
    $scripthash{$_->scripthash} = 1 foreach grep { $_->value > 0 } @{$tx->out};
    $GENESIS_SCRIPTHASHES = \%scripthash if %scripthash;
    return;
}

sub add_coinbase { my (undef, $value) = @_; $UPGRADE_TOTAL += $value if $INITIALIZED }
sub del_coinbase { my (undef, $value) = @_; $UPGRADE_TOTAL -= $value if $INITIALIZED }
sub add_static   { my (undef, $value) = @_; $STATIC_TOTAL  += $value if $INITIALIZED }
sub del_static   { my (undef, $value) = @_; $STATIC_TOTAL  -= $value if $INITIALIZED }

# Sum of static block rewards for the whole best branch up to the given tip.
# Static reward is zero until the upgrade is finished, so this is 0 during the upgrade
# phase. After the upgrade the per-block reward depends only on the block height
# (halving), so the sum has a closed form over the halving epochs.
# NB: this base ignores empty blocks (which pay no reward) and so may slightly
# over-count if the node is restarted long after the upgrade has finished; the forward
# accounting via confirm/unconfirm is exact.
sub _static_total {
    my ($tip) = @_;
    return 0 unless $tip;
    my $h_end = _first_static_height($tip);
    return 0 unless defined $h_end;
    return _halving_sum($h_end, $tip->height);
}

# The upgrade is finished for the given block (so its static reward is non-zero).
# This condition is monotonic by height.
sub _upgrade_ended {
    my ($block) = @_;
    return 1 if !UPGRADE_POW;
    return 1 if Bitcoin::Block->upgrade_stopped(timeslot($block->time));
    return 0 if $block->height < 1;
    my ($prev) = QBitcoin::Block->find(height => $block->height - 1);
    return $prev && (($prev->upgraded // 0) >= UPGRADE_MAX_VALUE || $prev->upgrade_stopped) ? 1 : 0;
}

# The lowest height at which the static reward becomes non-zero, or undef if the
# upgrade is not finished even at the tip. Binary search relies on monotonicity.
sub _first_static_height {
    my ($tip) = @_;
    return undef unless _upgrade_ended($tip);
    my $lo = 1;
    my $hi = $tip->height;
    while ($lo < $hi) {
        my $mid = int(($lo + $hi) / 2);
        my ($block) = QBitcoin::Block->find(height => $mid);
        if ($block && _upgrade_ended($block)) {
            $hi = $mid;
        }
        else {
            $lo = $mid + 1;
        }
    }
    return $lo;
}

# Sum of int(STATIC_REWARD / 2**int((h-1)/REWARD_HALVING)) for h in [$from .. $to].
# The reward is constant within a halving epoch, so iterate epoch by epoch.
sub _halving_sum {
    my ($from, $to) = @_;
    my $total = 0;
    for (my $h = $from; $h <= $to; ) {
        my $epoch  = int(($h - 1) / REWARD_HALVING);
        my $reward = int(STATIC_REWARD / 2**$epoch);
        last if $reward <= 0;
        my $seg_end = ($epoch + 1) * REWARD_HALVING; # last height of this epoch
        $seg_end = $to if $seg_end > $to;
        $total += $reward * ($seg_end - $h + 1);
        $h = $seg_end + 1;
    }
    return $total;
}

1;
