package QBitcoin::Downgrade::Reclaim;
use warnings;
use strict;

# Auto-reclaim for the trustless downgrade — the user-safety backstop.
#
# Once the relative time-lock has elapsed (48h for a freeze output, 7 days for a
# downgrade output) and the matching system step never appeared, the node that
# holds the user's reclaim key spends the output's ELSE branch back to the user's
# own address. Runs once per block cycle from QBitcoin::Generate.
#
# The reclaim_id (hash160/hash256 of the user pubkey) is stored at the front of
# the output data; the rest is the BTC scriptPubKey, which the reclaim ignores.

use QBitcoin::Log;
use QBitcoin::Const;
use QBitcoin::ORM qw(dbh DEBUG_ORM);
use QBitcoin::MyAddress;
use QBitcoin::Crypto qw(hash160);
use QBitcoin::RedeemScript;
use QBitcoin::TXO;
use QBitcoin::Transaction;
use QBitcoin::Address qw(scripthash_by_address);

use constant MAX_RECLAIM_PER_CYCLE => 10;

# [ scripthash, redeem_script, reclaim_id length, relative time-lock seconds ]
sub _reclaim_kinds {
    return (
        [ hash160(QBT_FREEZE_SCRIPT),    QBT_FREEZE_SCRIPT,    32, DOWNGRADE_FREEZE_SEC ],
        [ hash160(QBT_DOWNGRADE_SCRIPT), QBT_DOWNGRADE_SCRIPT, 32, DOWNGRADE_OUTPUT_SEC ],
    );
}

# Scan for reclaimable freeze/downgrade outputs and build reclaim transactions.
sub scan_and_reclaim {
    my $class = shift;
    my ($now) = @_;
    $now //= time();
    my $count = 0;

    for my $kind (_reclaim_kinds()) {
        last if $count >= MAX_RECLAIM_PER_CYCLE;
        my ($scripthash, $redeem, $rlen, $csv_sec) = @$kind;
        my ($script_entry) = QBitcoin::RedeemScript->find(hash => $scripthash);
        next unless $script_entry;

        # Unspent outputs whose time-lock (relative to the confirming block's time)
        # has elapsed: block.time + csv_sec <= now.
        my $sql =
            "SELECT t.value, tx_in.hash AS tx_in, t.num, t.data"
          . " FROM `txo` AS t"
          . " JOIN `transaction` AS tx_in ON (tx_in.id = t.tx_in)"
          . " JOIN `block` AS b ON (b.height = tx_in.block_height)"
          . " WHERE t.tx_out IS NULL AND t.scripthash = ?"
          . " AND tx_in.block_height IS NOT NULL AND b.time + ? <= CAST(? AS INTEGER)"
          . " LIMIT ?";
        DEBUG_ORM && Debugf("sql: [%s] values [%u,%u,%u,%u]", $sql, $script_entry->id, $csv_sec, $now, MAX_RECLAIM_PER_CYCLE);
        my $sth = dbh->prepare($sql);
        $sth->execute($script_entry->id, $csv_sec, $now, MAX_RECLAIM_PER_CYCLE);

        while (my $row = $sth->fetchrow_hashref()) {
            last if $count >= MAX_RECLAIM_PER_CYCLE;
            my $reclaim_id = substr($row->{data} // "", 0, $rlen);
            next unless length($reclaim_id) == $rlen;
            my $address = QBitcoin::MyAddress->get_by_pubkeyhash($reclaim_id)
                or next;  # not our key
            my $txo = QBitcoin::TXO->new_saved({
                value      => $row->{value},
                tx_in      => $row->{tx_in},
                num        => $row->{num},
                scripthash => $scripthash,
                data       => $row->{data},
            });
            next unless $txo->unspent;  # already being spent in a mempool tx
            my $tx = $class->_build_reclaim_tx($txo, $address, $redeem)
                or next;
            Infof("Auto-reclaim %s:%u (%lu) → tx %s",
                unpack("H*", $txo->tx_in), $txo->num, $txo->value, $tx->hash_str);
            $count++;
        }
    }
    return $count;
}

sub _build_reclaim_tx {
    my ($class, $txo, $address, $redeem_script) = @_;

    my $out_scripthash = scripthash_by_address($address->address)
        or do {
            Errf("Can't get scripthash for reclaim address %s", $address->address // "?");
            return undef;
        };
    my $out = QBitcoin::TXO->new_txo({ value => $txo->value, scripthash => $out_scripthash });

    my $tx = QBitcoin::Transaction->new(
        in            => [ { txo => $txo } ],
        out           => [ $out ],
        fee           => 0,
        tx_type       => TX_TYPE_STANDARD,
        received_time => time(),
    );
    $tx->make_sign_reclaim($tx->in->[0], $address, 0, $redeem_script);
    $tx->calculate_hash;

    if (QBitcoin::Transaction->check_by_hash($tx->hash)) {
        Debugf("Reclaim tx %s already known", $tx->hash_str);
        return undef;
    }

    QBitcoin::TXO->save_all($tx->hash, $tx->out);
    $txo->spent_add($tx);
    if ($tx->validate() != 0) {
        Errf("Generated reclaim tx %s is invalid", $tx->hash_str);
        $txo->spent_del($tx);
        return undef;
    }
    $tx->save();
    $tx->announce();
    return $tx;
}

1;
