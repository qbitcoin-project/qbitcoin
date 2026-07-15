package QBitcoin::Block;
use warnings;
use strict;
use feature 'state';

use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::ORM qw(dbh :types);
use QBitcoin::Accessors qw(mk_accessors new);
use QBitcoin::Config;
use QBitcoin::ProtocolState qw(skip_scripts);
use QBitcoin::Transaction;
use QBitcoin::ValueUpgraded qw(level_by_total upgrade_value);
use QBitcoin::Crypto qw(hash256);
use Bitcoin::Block;

use Role::Tiny::With;
with 'QBitcoin::Block::Receive';
with 'QBitcoin::Block::Validate';
with 'QBitcoin::Block::Serialize';
with 'QBitcoin::Block::Stored';
with 'QBitcoin::Block::MerkleTree';
with 'QBitcoin::Block::Pending';

use constant PRIMARY_KEY => 'height';

use constant FIELDS => {
    height      => NUMERIC,
    time        => NUMERIC,
    hash        => BINARY,
    size        => NUMERIC,
    weight      => NUMERIC,
    upgraded    => NUMERIC,
    downgraded  => NUMERIC,
    downgrade_pinned => NUMERIC, # cumulative qbtc value pinned by downgrade txs (for reorg-penalty weight accounting)
    reward_fund => NUMERIC,
    min_fee     => NUMERIC,
    prev_hash   => BINARY,
    merkle_root => BINARY,
};

use constant ATTR => qw(
    next_block
    received_from
    rcvd
);

mk_accessors(keys %{&FIELDS});
mk_accessors(ATTR);

sub branch_height {
    my $self = shift;
    while ($self->next_block) {
        $self = $self->next_block;
    }
    return $self->height;
}

# Feerate (satoshi per kb) of the cheapest fee-paying standard or tokens transaction
# in the block, undef if there are no such transactions.
# It is the market anchor for the next block min_fee (see QBitcoin::MinFee).
# Derived attribute, not stored in the database: computed from the in-memory
# transactions (block validation caches it), or fetched by a single query
# for blocks loaded from the database (deep reorg beyond incore levels).
sub min_tx_fee {
    my $self = shift;
    unless (exists $self->{min_tx_fee}) {
        my $min_tx_fee;
        if ($self->{transactions}) {
            foreach my $transaction (@{$self->{transactions}}) {
                next unless ($transaction->is_standard || $transaction->is_tokens) && $transaction->fee > 0;
                my $fee_per_kb = int($transaction->fee * 1024 / $transaction->size);
                $min_tx_fee = $fee_per_kb if !defined($min_tx_fee) || $fee_per_kb < $min_tx_fee;
            }
        }
        elsif ($self->{tx_by_hash}) {
            die "Get min_tx_fee from not-loaded block\n";
        }
        else {
            # MIN() and FLOOR() commute (floor is monotone), so the aggregate can floor
            # on the sql side. (fee*1024 - fee*1024 % size) is divisible by size, which
            # makes the division exact in both mysql and sqlite: plain fee*1024/size
            # would be ROUNDED decimal division in mysql (may cross an integer boundary
            # upwards) but truncated integer division in sqlite, and FLOOR() may be
            # missing in sqlite builds
            ($min_tx_fee) = dbh->selectrow_array(
                "SELECT MIN((fee*1024 - fee*1024 % size) / size) FROM `" . QBitcoin::Transaction->TABLE . "`" .
                " WHERE block_height = ? AND fee > 0 AND tx_type IN (?,?)",
                undef, $self->height, TX_TYPE_STANDARD, TX_TYPE_TOKENS);
            # mysql returns the decimal division result as a string like "11.0000"
            $min_tx_fee = int($min_tx_fee) if defined $min_tx_fee;
        }
        $self->{min_tx_fee} = $min_tx_fee;
    }
    return $self->{min_tx_fee};
}

sub self_weight {
    my $self = shift;
    if (!defined $self->{self_weight}) {
        if (skip_scripts()) {
            my $prev = $self->prev_block_load;
            $self->{self_weight} = $self->weight - ($prev ? $prev->weight : 0);
        }
        elsif (@{$self->transactions}) {
            if (defined(my $stake_weight = $self->transactions->[0]->stake_weight($self))) {
                my $weight = $stake_weight + @{$self->transactions};
                my $ok = 1;
                # coinbase increases block weight
                foreach my $transaction (@{$self->transactions}) {
                    if ($transaction->is_coinbase) {
                        $weight += $transaction->coinbase_weight($self->time);
                    }
                    elsif ($transaction->is_slashing) {
                        # The slashed stake inputs count toward block weight exactly like
                        # stake inputs, so a slashing tx can outweigh the stake it punishes.
                        my $w = $transaction->slashing_weight($self->time);
                        if (!defined $w) {
                            $ok = 0;
                            last;
                        }
                        $weight += $w;
                    }
                    elsif ($transaction->is_burn) {
                        $weight += $transaction->burn_weight($self->time);
                    }
                    elsif ($transaction->is_downgrade) {
                        $weight += $transaction->downgrade_weight($self->time);
                    }
                    else {
                        last if $transaction->fee >= 0;
                        next;
                    }
                }
                # $ok false => a slashing input is not yet confirmed; leave self_weight
                # undef and recalculate next time (same as an unknown stake input).
                $self->{self_weight} = $weight if $ok;
            }
            # otherwise we have unknown input in stake transaction; return undef and calculate next time
        }
        else {
            $self->{self_weight} = 0;
        }
        if (defined($self->{self_weight}) && (timeslot($self->time) - GENESIS_TIME) / BLOCK_INTERVAL % FORCE_BLOCKS == 0) {
            $self->{self_weight} += 1;
        }
    }
    return $self->{self_weight};
}

sub add_tx {
    my $self = shift;
    my ($tx) = @_;
    $self->{tx_by_hash} //= {};
    $self->{tx_by_hash}->{$tx->hash} = $tx;
    $tx->add_to_block($self);
    delete $self->{pending_tx}->{$tx->hash} if $self->pending_tx;
}

sub pending_tx {
    my $self = shift;
    my ($tx_hash) = @_;
    if ($tx_hash) {
        $self->{pending_tx} //= {};
        $self->{pending_tx}->{$tx_hash} = 1;
        return 1;
    }
    else {
        return $self->{pending_tx} && %{$self->{pending_tx}} ? keys %{$self->{pending_tx}} : ();
    }
}

sub compact_tx {
    my $self = shift;
    if ($self->{transactions}) {
        die "Call compact_tx with already defined transactions for block " . $self->hash_str . " height " . $self->height . "\n";
    }
    $self->{transactions} = [ map { $self->{tx_by_hash}->{$_} } @{$self->{tx_hashes}} ];
    delete $self->{tx_by_hash};
}

sub free_tx {
    my $self = shift;
    # works for pending block too
    if ($self->{transactions}) {
        foreach my $tx (@{$self->{transactions}}) {
            $tx->del_from_block($self);
        }
    }
    elsif ($self->{tx_by_hash}) {
        foreach my $tx (values %{$self->{tx_by_hash}}) {
            $tx->del_from_block($self);
        }
    }
}

# Data signed by the block's stake transaction. To keep slashing evidence small we
# commit to the transaction list via a single hash256 (not the full list) and we sign
# the timeslot explicitly: equivocation == the same stake UTXO signing two different
# blocks (different prev_hash/digest) in the same timeslot. The first tx (the stake
# itself) is excluded because its hash depends on this very signature.
sub sign_data {
    my $self = shift;
    my $data = ($self->prev_hash // ZERO_HASH) . pack("N", timeslot($self->time));
    my $num = 0;
    my $tx_hashes = "";
    foreach (@{$self->tx_hashes}) {
        $tx_hashes .= $_ if $num++;
    }
    return $data . hash256($tx_hashes);
}

sub hash_str {
    my $arg  = pop;
    my $hash = ref($arg) ? $arg->hash : $arg;
    return unpack("H*", substr($hash, 0, 4));
}

sub reward {
    my $class = shift;
    my ($prev_block, $fee, $time) = @_;
    if ($prev_block) {
        my $reward = 0;
        if (my $reward_fund = $prev_block->reward_fund + $fee) {
            $reward = int($reward_fund / REWARD_DIVIDER) || 1;
        }
        $reward += $class->static_reward($prev_block, $time);
        return $reward;
    }
    else {
        return $config->{regtest} ? $config->{genesis_reward} // 0 : GENESIS_REWARD;
    }
}

sub static_reward {
    my $class = shift;
    my ($prev_block, $time) = @_;
    my $static_reward = 0;
    if ($prev_block) {
        my $timeslot = timeslot($time);
        if (!UPGRADE_POW || $prev_block->upgraded >= UPGRADE_MAX_VALUE || Bitcoin::Block->upgrade_stopped($timeslot)) {
            $static_reward = int(STATIC_REWARD / 2**int(($timeslot - GENESIS_TIME) / BLOCK_INTERVAL / REWARD_HALVING));
            $static_reward *= ($timeslot - timeslot($prev_block->time)) / BLOCK_INTERVAL;
        }
    }
    return $static_reward;
}

sub reorg_penalty {
    my $self = shift;
    my ($branch_start) = @_;

    # It's not consensus rule, so we're able to use floating point arithmetic here
    # It should be overweight twice for revert last 16 blocks, 4 times for 32 blocks, 8 times for 64 blocks, 16 times for 128 blocks, 32 times for 256 blocks
    # But then decrease for prevent split-brain: 32 times for 900; 16 times for 3600; 8 times for 14400 blocks (~1 day), 4 times for 57600 blocks, 2 times for 230400 blocks, and no penalty for 921600 blocks (~3 months)

    if (!$branch_start) {
        Warningf("No reorg penalty for change genesis block");
        return 0;
    }
    return 0 if $self->height - $branch_start->height < INCORE_LEVELS;
    my $reorg_blocks = (timeslot($self->time) - timeslot($branch_start->time)) / BLOCK_INTERVAL - FORCE_BLOCKS;
    return 0 if $reorg_blocks <= 0;
    my $upgraded_btc   = $self->upgraded   - $branch_start->upgraded;
    my $downgraded_btc = ($self->downgraded // 0) - ($branch_start->downgraded // 0);
    my $coinbase_btc   = $upgraded_btc + $downgraded_btc; # gross BTC from coinbases
    my $level_end   = level_by_total($self->upgraded);
    my $level_start = level_by_total($branch_start->upgraded);
    my $coinbase_qbtc = sqrt(upgrade_value($coinbase_btc, $level_end) * upgrade_value($coinbase_btc, $level_start)); # not fully accurate, but good enough for penalty calculation
    my $burn_qbtc     = sqrt(upgrade_value($downgraded_btc, $level_end) * upgrade_value($downgraded_btc, $level_start));
    # Downgrade txs carry the same age-independent weight as burns; exclude it from
    # stake_weight so the reorg penalty does not eat the anti-reorg pinning weight.
    my $downgrade_qbtc = ($self->downgrade_pinned // 0) - ($branch_start->downgrade_pinned // 0);
    my $coinbase_weight = ($coinbase_qbtc * COINBASE_WEIGHT_TIME + ($burn_qbtc + $downgrade_qbtc) * QBT_BURN_VIRT_AGE) / BLOCK_INTERVAL;
    my $stake_weight = $self->weight - $branch_start->weight - $coinbase_weight;
    return 0 if $stake_weight <= 0;
    my $coef;
    if ($reorg_blocks < 248) {
        $coef = $reorg_blocks / 8 + 1;
    }
    elsif ($reorg_blocks < 900) {
        $coef = 32;
    }
    elsif ($reorg_blocks < 921600) {
        $coef = 960 / sqrt($reorg_blocks);
    }
    else {
        $coef = 1;
    }
    Debugf("Reorg penalty for block %s height %u (%u reorg blocks, %u seconds): %.2f%%, %.0f",
        $self->hash_str, $self->height, $self->height - $branch_start->height,
        $self->time - $branch_start->time, ($coef - 1) * 100, ($coef - 1) * $stake_weight);
    return ($coef - 1) * $stake_weight;
}

sub delete_since_height {
    my ($class, $height) = @_;
    my $tx_class = 'QBitcoin::Transaction';
    # Load and unconfirm transactions from stored blocks to restore UTXO state
    foreach my $tx_hashref ($tx_class->fetch( block_height => { '>=', $height }, -sortby => 'block_height DESC, block_pos DESC')) {
        my $tx = $tx_class->get($tx_hashref->{hash});
        if (!$tx) {
            $tx_class->pre_load($tx_hashref);
            $tx = $tx_class->new($tx_hashref);
            if ($tx->validate_hash) {
                foreach my $in (@{$tx->in}) {
                    $in->{txo}->spent_del($tx);
                }
                next;
            }
            $tx->add_to_cache;
        }
        $tx->unconfirm();
    }
    # Delete blocks from DB in one query (cascades to transactions)
    $class->delete_by(height => { '>' => $height });
}

1;
