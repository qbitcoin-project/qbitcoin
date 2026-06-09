package QBitcoin::ValueUpgraded;
use warnings;
use strict;
use feature 'state';

use QBitcoin::Config;
use QBitcoin::Log;
use QBitcoin::Accessors qw(mk_accessors new);
use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::ORM qw(find create :types);
use QBitcoin::ValueUpgraded::PriceByLevel qw(@price_by_level);

use Exporter qw(import);
our @EXPORT_OK = qw(level_by_total upgrade_value downgrade_value downgrade_value_at_level downgrade_net);

use constant TABLE => 'value_upgraded';

use constant PRIMARY_KEY => 'block_height';

use constant FIELDS => {
    block_height => NUMERIC,
    value        => NUMERIC,
    total        => NUMERIC,
};

mk_accessors(keys %{&FIELDS});

sub level_by_total {
    my ($total) = @_;

    return int($total * 5000 / MAX_VALUE);
}

sub price_by_level {
    my ($level) = @_;

    # return 0.999**$level;
    # Avoid floating point arithmetic
    return $price_by_level[$level];
}

sub upgrade_value {
    my ($value, $level) = @_;

    return int($value * $price_by_level[$level] / 1000000);
}

# BTC value for `$value` qbtc at a fixed upgrade level — the pure rate conversion
# (mirror of upgrade_value() on the other side), with NO reserve cap. Use this for
# the downgrade floor at level 0 (the worst rate for the user): it is fork-agnostic
# because it reads price_by_level[0] instead of assuming a 1:1 start rate.
sub downgrade_value_at_level {
    my ($value, $level) = @_;

    return int($value * 1000000 / $price_by_level[$level]);
}

sub downgrade_value {
    my ($value, $upgraded) = @_;

    my $level = level_by_total($upgraded);
    my $btc_value = downgrade_value_at_level($value, $level);
    $btc_value = $upgraded if $btc_value > $upgraded;
    while ($level > 0 && level_by_total($upgraded - $btc_value) < $level) {
        $level--;
        $btc_value = downgrade_value_at_level($value, $level);
        $btc_value = $upgraded if $btc_value > $upgraded;
    }
    return $btc_value;
}

# BTC value actually released to the user after the downgrade service fee.
# Mirrors coinbase_value() on the upgrade side (which applies UPGRADE_FEE).
# NB: downgrade_value() above stays fee-free — it is used for upgrade-level
# accounting; the fee only reduces what the user receives.
sub downgrade_net {
    my ($value) = @_;
    state $permil = 1000 - int(DOWNGRADE_FEE * 1000);
    use integer;
    return $value * $permil / 1000;
}

1;
