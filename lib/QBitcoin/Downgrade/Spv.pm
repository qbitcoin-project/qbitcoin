package QBitcoin::Downgrade::Spv;
use warnings;
use strict;
use feature 'state';

# BTC SPV proof of the payment for a downgrade (storage only).
#
# A row is created by the BTC watcher when it sees the funding transaction of a
# pending downgrade (matched by committed txid). While burn_tx_id IS NULL it is an
# observed-but-not-yet-burned payment awaiting confirmations; once a burn is built
# or received, burn_tx_id points to it and the row also persists that burn's proof.
#
# A BTC reorg is handled explicitly (delete_pending_above) and only drops pending
# rows, so a confirmed burn keeps its proof (mirrors the coinbase handling).

use Scalar::Util qw(weaken refaddr);
use QBitcoin::Accessors qw(new mk_accessors);
use QBitcoin::Log;
use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::ORM qw(:types dbh fetch find create DEBUG_ORM);
use QBitcoin::Crypto qw(hash256);
use QBitcoin::RedeemScript;
use Bitcoin::Block;

use constant TABLE => 'downgrade_spv';
use constant PRIMARY_KEY => 'downgrade_tx_id';

use constant FIELDS => {
    downgrade_tx_id  => NUMERIC,
    btc_block_height => NUMERIC,
    btc_block_hash   => BINARY,
    btc_tx_num       => NUMERIC,
    btc_tx_hash      => BINARY,
    merkle_path      => BINARY,
    btc_tx_data      => BINARY,
    burn_tx_id       => NUMERIC,
};

mk_accessors(keys %{&FIELDS});

my %SPV; # short-lived cache of recently produced (not yet burned) entries

# Map { committed_btc_txid => downgrade_tx_id } of pending downgrades whose BTC
# payment has not been recorded yet (no SPV row). Rebuilt per BTC block.
#
# Driven from the unspent downgrade-output set (scripthash + tx_out IS NULL) so the
# cost scales with the number of *pending* downgrades, not with all downgrades ever:
# the txo(tx_out, scripthash) index turns it into a direct seek. Driving from the
# `downgrade` table instead would full-scan every downgrade ever made.
sub pending_txids {
    my $class = shift;
    state $script;
    $script //= QBitcoin::RedeemScript->find(hash => QBT_DOWNGRADE_SCRIPTHASH)
        or return {};
    my $sql =
        "SELECT d.btc_txid, d.tx_id FROM `txo` AS o"
      . " JOIN `downgrade` AS d ON (d.tx_id = o.tx_in)"
      . " LEFT JOIN `" . TABLE . "` AS sv ON (sv.downgrade_tx_id = o.tx_in)"
      . " WHERE o.scripthash = ? AND o.num = 0 AND o.tx_out IS NULL AND sv.downgrade_tx_id IS NULL";
    my $sth = dbh->prepare($sql);
    $sth->execute($script->id);
    my %pending;
    while (my $row = $sth->fetchrow_hashref()) {
        $pending{$row->{btc_txid}} = $row->{tx_id};
    }
    return \%pending;
}

# Confirmed, not-yet-burned SPVs whose downgrade output is still unspent. Each row
# also carries what the burn builder needs: downgrade-tx hash, output value/data/script.
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
        "SELECT sv.downgrade_tx_id, sv.btc_block_height, sv.btc_block_hash, sv.btc_tx_num, sv.btc_tx_hash, sv.merkle_path, sv.btc_tx_data,"
      . " tx.hash AS dg_tx_hash, o.value AS dg_value, o.data AS dg_data, s.hash AS dg_scripthash"
      . " FROM `" . TABLE . "` AS sv"
      . " JOIN `transaction`   AS tx ON (tx.id = sv.downgrade_tx_id)"
      . " JOIN `txo`           AS o  ON (o.tx_in = sv.downgrade_tx_id AND o.num = 0)"
      . " JOIN `redeem_script` AS s  ON (s.id = o.scripthash)"
      . " WHERE sv.burn_tx_id IS NULL AND sv.btc_block_height IS NOT NULL"
      . " AND sv.btc_block_height <= ? AND o.tx_out IS NULL";
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

# Persist the proof for a burn transaction (link an existing detection row, or
# insert one if this node never detected the payment, e.g. received the burn).
sub store_burn {
    my $class = shift;
    my ($downgrade_tx_hash, $proof, $burn_tx_id) = @_;
    my ($dg_id) = dbh->selectrow_array("SELECT id FROM `transaction` WHERE hash = UNHEX(?)", undef, unpack("H*", $downgrade_tx_hash));
    defined $dg_id or die "store_burn: no downgrade transaction for burn\n";
    if (dbh->selectrow_array("SELECT 1 FROM `" . TABLE . "` WHERE downgrade_tx_id = ?", undef, $dg_id)) {
        dbh->do("UPDATE `" . TABLE . "` SET burn_tx_id = ? WHERE downgrade_tx_id = ?", undef, $burn_tx_id, $dg_id);
    }
    else {
        my ($btc_block) = Bitcoin::Block->find(hash => $proof->btc_block_hash);
        $class->create({
            downgrade_tx_id  => $dg_id,
            btc_block_height => ($btc_block ? $btc_block->height : undef),
            btc_block_hash   => $proof->btc_block_hash,
            btc_tx_num       => $proof->btc_tx_num,
            btc_tx_hash      => hash256($proof->btc_tx_data),
            merkle_path      => $proof->merkle_path,
            btc_tx_data      => $proof->btc_tx_data,
            burn_tx_id       => $burn_tx_id,
        });
    }
}

# BTC reorg: drop only the not-yet-burned SPVs at or above the reverted height
# (their payment may have moved); confirmed burns keep their proof.
sub delete_pending_above {
    my $class = shift;
    my ($height) = @_;
    dbh->do("DELETE FROM `" . TABLE . "` WHERE burn_tx_id IS NULL AND btc_block_height > ?", undef, $height);
}

sub DESTROY {
    my $self = shift;
    my $key = $self->{downgrade_tx_id};
    if (defined($key) && (!defined($SPV{$key}) || refaddr($self) == refaddr($SPV{$key}))) {
        delete $SPV{$key};
    }
}

1;
