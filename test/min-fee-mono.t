#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use QBitcoin::MinFee qw(min_fee MIN_FEE);

# Unit test for the market-anchored min_fee rule:
# - within the tolerance band around prev size the bar is (min_tx_fee + 1), both ways
# - outside the band the size-based formula applies with monotonicity clamps:
#   min(pin, formula) below prev size, max(pin, formula) above it
# - the pin may not drop the bar below prev min_fee * MIN_FEE_REDUCE in one block

package MockBlock;
sub new {
    my ($class, $min_fee, $size, $min_tx_fee) = @_;
    return bless { min_fee => $min_fee, size => $size, min_tx_fee => $min_tx_fee }, $class;
}
sub min_fee    { $_[0]->{min_fee} }
sub size       { $_[0]->{size} }
sub min_tx_fee { $_[0]->{min_tx_fee} }

package main;

# In-band: bar is anchored to the cheapest paid feerate + 1
my $prev = MockBlock->new(100, 100_000, 100);
is(min_fee($prev, 100_000), 101, "equal size: bar = min_tx_fee + 1");
is(min_fee($prev,  95_000), 101, "in-band shrink: bar = min_tx_fee + 1");
is(min_fee($prev, 105_000), 101, "in-band growth: bar = min_tx_fee + 1");

# Re-anchoring down: a sub-bar mass pulls the bar to just above its top,
# but not faster than the regular decay allows
my $mass = MockBlock->new(100, 100_000, 50);
is(min_fee($mass, 100_000), 90, "descent to the mass is rate-limited by MIN_FEE_REDUCE");
my $mass2 = MockBlock->new(52, 100_000, 50);
is(min_fee($mass2, 100_000), 51, "bar settles just above the mass top");

# Out-of-band growth: priced by the formula, never below the pin
is(min_fee($prev, 200_000), 200, "sharp growth: proportional formula price");
my $locked = MockBlock->new(51, 100_000, 50);
is(min_fee($locked, 112_000), 57, "growth just out of band: formula from the anchored bar");

# Out-of-band shrink: formula decay, never above the pin (monotonicity)
is(min_fee($prev, 80_000), 72, "sharp shrink: formula decay below the pin");
is(min_fee($mass2, 80_000), 37, "sharp shrink with mass: decay may flush below the mass");

# Clamps
my $tiny_anchor = MockBlock->new(10, 100_000, 3);
is(min_fee($tiny_anchor, 100_000), MIN_FEE, "pin clamped to MIN_FEE floor");
my $no_anchor = MockBlock->new(100, 100_000, undef);
is(min_fee($no_anchor, 100_000), 90, "no fee-paying txs in prev block: size-based formula");
is(min_fee($prev, 200), 0, "tiny block resets min_fee");
is(min_fee(undef, 1000), MIN_FEE, "no previous block: MIN_FEE");

# Monotonicity sweep: required min_fee must never decrease as the block grows
my $m = MockBlock->new(100, 100_000, 60);
my $last = 0;
my $ok = 1;
for (my $size = 1000; $size <= 300_000; $size += 1000) {
    my $fee = min_fee($m, $size);
    $ok = 0, last if $fee < $last && $size >= 256;
    $last = $fee;
}
ok($ok, "min_fee is monotonically non-decreasing in block size");

done_testing();
