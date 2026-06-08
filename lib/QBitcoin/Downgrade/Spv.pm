package QBitcoin::Downgrade::Spv;
use warnings;
use strict;

# An observed BTC payment for a pending downgrade, awaiting confirmations before a
# burn transaction is generated from it. The node watches the BTC chain (as it does
# for upgrade coinbases) and, when it sees a BTC transaction whose txid matches a
# pending downgrade commitment, builds the merkle path and stores it here, linked to
# the BTC block. ON DELETE CASCADE on the BTC block makes a BTC reorg drop the row.
#
# get_new() returns rows whose BTC payment is deeply enough confirmed
# (COINBASE_CONFIRM_BLOCKS blocks AND COINBASE_CONFIRM_TIME, same rule as coinbases),
# so a small BTC reorg can't flip a burn between valid and invalid.

use Scalar::Util qw(weaken refaddr);
use QBitcoin::Accessors qw(new mk_accessors);
use QBitcoin::Log;
use QBitcoin::Const;
use QBitcoin::ORM qw(:types dbh find create delete_by DEBUG_ORM);
use QBitcoin::Crypto qw(hash160);
use QBitcoin::Downgrade;
use QBitcoin::TXO;
use QBitcoin::Transaction;
use Bitcoin::Serialized;
use Bitcoin::Block;

use constant TABLE => 'downgrade_spv';
use constant PRIMARY_KEY => 'downgrade_tx_id';

use constant FIELDS => {
    downgrade_tx_id  => NUMERIC,
    btc_block_height => NUMERIC,
    btc_tx_num       => NUMERIC,
    btc_tx_hash      => BINARY,
    merkle_path      => BINARY,
    btc_tx_data      => BINARY,
};

mk_accessors(keys %{&FIELDS});

my %SPV; # short-lived cache of recently produced entries (by downgrade_tx_id)

# Return SPV records whose BTC payment is confirmed deeply enough to burn and whose
# downgrade output is still unspent. Each returned object also carries the data
# needed to build the burn: the downgrade-tx hash and its output value/data/script.
sub get_new {
    my $class = shift;
    my ($time) = @_;

    my ($matched_block) = Bitcoin::Block->find(
        time    => { '<' => $time - COINBASE_CONFIRM_TIME },
        -sortby => 'height DESC',
        -limit  => 1,
    );
    return () unless $matched_block;
    my $max_height = $matched_block->height - COINBASE_CONFIRM_BLOCKS;

    my $sql =
        "SELECT sv.downgrade_tx_id, sv.btc_block_height, sv.btc_tx_num, sv.btc_tx_hash, sv.merkle_path, sv.btc_tx_data,"
      . " tx.hash AS dg_tx_hash, o.value AS dg_value, o.data AS dg_data, s.hash AS dg_scripthash"
      . " FROM `" . TABLE . "` AS sv"
      . " JOIN `transaction`   AS tx ON (tx.id = sv.downgrade_tx_id)"
      . " JOIN `txo`           AS o  ON (o.tx_in = sv.downgrade_tx_id AND o.num = 0)"
      . " JOIN `redeem_script` AS s  ON (s.id = o.scripthash)"
      . " WHERE sv.btc_block_height IS NOT NULL AND sv.btc_block_height <= ? AND o.tx_out IS NULL";
    DEBUG_ORM && Debugf("sql: [%s] values [%d]", $sql, $max_height);
    my $sth = dbh->prepare($sql);
    $sth->execute($max_height);
    my @spv;
    while (my $hash = $sth->fetchrow_hashref()) {
        next if defined($SPV{$hash->{downgrade_tx_id}}); # burn already produced (not yet confirmed)
        my $spv = $class->new($hash);
        $SPV{$hash->{downgrade_tx_id}} = $spv;
        weaken($SPV{$hash->{downgrade_tx_id}});
        push @spv, $spv;
    }
    DEBUG_ORM && Debugf("found %u downgrade spv entries", scalar @spv);
    return @spv;
}

# Map { committed_btc_txid => downgrade_tx_id } of pending downgrades whose BTC
# payment has not been recorded yet (no SPV row). Rebuilt from the database; the
# set is small (only in-flight downgrades), so it is cheap to recompute per BTC
# block. Used by the BTC watcher to recognize the funding transaction.
sub pending_txids {
    my $class = shift;
    my $sql =
        "SELECT d.payload, d.tx_id FROM `downgrade` AS d"
      . " JOIN `transaction`  AS tx ON (tx.id = d.tx_id)"
      . " JOIN `txo`          AS o  ON (o.tx_in = d.tx_id AND o.num = 0)"
      . " LEFT JOIN `" . TABLE . "` AS sv ON (sv.downgrade_tx_id = d.tx_id)"
      . " WHERE tx.tx_type = ? AND o.tx_out IS NULL AND sv.downgrade_tx_id IS NULL";
    my $sth = dbh->prepare($sql);
    $sth->execute(TX_TYPE_DOWNGRADE);
    my %pending;
    while (my $row = $sth->fetchrow_hashref()) {
        my $commit = QBitcoin::Downgrade->deserialize_commitment(Bitcoin::Serialized->new($row->{payload}))
            or next;
        $pending{$commit->btc_txid} = $row->{tx_id};
    }
    return \%pending;
}

# Build burn transactions for all confirmed downgrade SPVs and add them to mempool.
sub generate_burns {
    my $class = shift;
    my ($time) = @_;
    my $count = 0;
    for my $spv ($class->get_new($time)) {
        my $tx = $class->_build_burn_tx($spv)
            or next;
        Infof("Generated downgrade burn %s for downgrade tx_id %u", $tx->hash_str, $spv->downgrade_tx_id);
        $count++;
    }
    return $count;
}

sub _build_burn_tx {
    my ($class, $spv) = @_;

    my $dg_sh  = $spv->{dg_scripthash};
    my $redeem = $dg_sh eq hash160(QBT_DOWNGRADE_SCRIPT)    ? QBT_DOWNGRADE_SCRIPT
               : $dg_sh eq hash160(QBT_DOWNGRADE_PQ_SCRIPT) ? QBT_DOWNGRADE_PQ_SCRIPT
               : return undef;
    my $txo = QBitcoin::TXO->new_saved({
        value      => $spv->{dg_value},
        tx_in      => $spv->{dg_tx_hash},
        num        => 0,
        scripthash => $dg_sh,
        data       => $spv->{dg_data},
    });
    return undef unless $txo->unspent;
    $txo->set_redeem_script($redeem);

    my ($btc_block) = Bitcoin::Block->find(height => $spv->btc_block_height);
    return undef unless $btc_block;
    my $proof = QBitcoin::Downgrade->new({
        btc_block_hash => $btc_block->hash,
        btc_tx_num     => $spv->btc_tx_num,
        merkle_path    => $spv->merkle_path,
        btc_tx_data    => $spv->btc_tx_data,
    });

    my $tx = QBitcoin::Transaction->new(
        in            => [ { txo => $txo, siglist => [ "\x01" ] } ],  # permissionless IF (TRUE selector)
        out           => [],
        fee           => $txo->value,
        tx_type       => TX_TYPE_BURN,
        down          => $proof,
        received_time => time(),
    );
    $tx->calculate_hash;
    if (QBitcoin::Transaction->check_by_hash($tx->hash)) {
        Debugf("Downgrade burn %s already known", $tx->hash_str);
        return undef;
    }
    $txo->spent_add($tx);
    if ($tx->validate() != 0) {
        Errf("Generated downgrade burn %s is invalid", $tx->hash_str);
        $txo->spent_del($tx);
        return undef;
    }
    $tx->save();
    $tx->announce();
    return $tx;
}

sub DESTROY {
    my $self = shift;
    my $key = $self->{downgrade_tx_id};
    if (defined($key) && (!defined($SPV{$key}) || refaddr($self) == refaddr($SPV{$key}))) {
        delete $SPV{$key};
    }
}

1;
