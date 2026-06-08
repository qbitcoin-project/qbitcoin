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

# Return SPV records whose BTC payment is confirmed deeply enough to burn.
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

    my $sql = "SELECT downgrade_tx_id, btc_block_height, btc_tx_num, btc_tx_hash, merkle_path, btc_tx_data"
            . " FROM `" . TABLE . "` WHERE btc_block_height IS NOT NULL AND btc_block_height <= ?";
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

sub DESTROY {
    my $self = shift;
    my $key = $self->{downgrade_tx_id};
    if (defined($key) && (!defined($SPV{$key}) || refaddr($self) == refaddr($SPV{$key}))) {
        delete $SPV{$key};
    }
}

1;
