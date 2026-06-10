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
use QBitcoin::Crypto qw(hash160);
use QBitcoin::Downgrade::Reclaim;

$config->{regtest} = 1;

my $now        = 2_000_000_000;
my $reclaim_id = "\x11" x 32;
my $spk        = "\x76\xa9\x14" . ("\xcc" x 20) . "\x88\xac";
my $data_hex   = unpack("H*", $reclaim_id . $spk);
my $freeze_sh  = hash160(QBT_FREEZE_SCRIPT);

my $freeze_sh_hex = unpack("H*", $freeze_sh);
my $dbh = dbh();
# redeem_script row for the EC freeze script (binary via hex literal to avoid NUL truncation)
$dbh->do("INSERT INTO redeem_script (id, hash) VALUES (1, X'$freeze_sh_hex')") or die $dbh->errstr;
my $rs_id = 1;

# Two blocks: one old enough for the 48h freeze lock, one too recent.
$dbh->do("INSERT INTO block (height,time,hash,size,weight,merkle_root) VALUES (1,?,X'a1',0,0,X'00')",
    undef, $now - DOWNGRADE_FREEZE_SEC - 100) or die $dbh->errstr;
$dbh->do("INSERT INTO block (height,time,hash,size,weight,merkle_root) VALUES (2,?,X'a2',0,0,X'00')",
    undef, $now) or die $dbh->errstr;

# Two freeze-creating transactions, one per block.
$dbh->do("INSERT INTO `transaction` (id,hash,block_height,block_pos,tx_type,size,fee) VALUES (1,X'aa',1,0,1,10,0)") or die $dbh->errstr;
$dbh->do("INSERT INTO `transaction` (id,hash,block_height,block_pos,tx_type,size,fee) VALUES (2,X'bb',2,0,1,10,0)") or die $dbh->errstr;

# Two unspent freeze outputs: txo1 (old block, eligible), txo2 (recent, not yet).
$dbh->do("INSERT INTO txo (value,num,tx_in,tx_out,scripthash,data) VALUES (1000,0,1,NULL,?,X'$data_hex')", undef, $rs_id) or die $dbh->errstr;
$dbh->do("INSERT INTO txo (value,num,tx_in,tx_out,scripthash,data) VALUES (1000,0,2,NULL,?,X'$data_hex')", undef, $rs_id) or die $dbh->errstr;

# We hold the reclaim key; _build_reclaim_tx is stubbed to just record selections.
my $addr_mod = Test::MockModule->new('QBitcoin::MyAddress');
$addr_mod->mock('get_by_pubkeyhash', sub { my ($c, $h) = @_; return $h eq $reclaim_id ? bless({}, 'QBitcoin::MyAddress') : undef });

my @built;
my $rec_mod = Test::MockModule->new('QBitcoin::Downgrade::Reclaim');
$rec_mod->mock('_build_reclaim_tx', sub { my ($c, $txo) = @_; push @built, unpack("H*", $txo->tx_in); return bless({}, 'FakeReclaimTx') });

my $count = QBitcoin::Downgrade::Reclaim->scan_and_reclaim($now);

is($count, 1, "exactly one output reclaimed (only the time-lock-elapsed one)");
is_deeply(\@built, ["aa"], "the old (block 1) freeze output was selected, not the recent one");

# Not our key → nothing reclaimed.
@built = ();
$addr_mod->mock('get_by_pubkeyhash', sub { undef });
is(QBitcoin::Downgrade::Reclaim->scan_and_reclaim($now), 0, "no reclaim when we don't hold the key");

done_testing();

package FakeReclaimTx;
sub hash_str { "fake_reclaim_tx" }
