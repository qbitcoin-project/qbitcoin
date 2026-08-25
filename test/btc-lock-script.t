#! /usr/bin/env perl
use warnings;
use strict;

# QBT_LOCK P2SH-P2WSH derivation chain: witnessScript -> redeemScript ->
# scriptSig template -> scriptPubKey -> Base58Check address, for all networks.

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;
use Digest::SHA qw(sha256);
use Crypt::PK::ECC;
use Encode::Base58::GMP qw(encode_base58);
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::Crypto qw(hash160 checksum32);
use Bitcoin::Address qw(scriptpubkey_to_btc_address);

sub base58check {
    my ($payload) = @_;
    return "" . encode_base58("0x" . unpack("H*", $payload . checksum32($payload)), "bitcoin");
}

# Parse a 2-of-3 CHECKMULTISIG witnessScript, return the pubkeys.
sub parse_multisig {
    my ($ws) = @_;
    is(length($ws), 105, "witnessScript length");
    is(substr($ws, 0, 1), "\x52", "OP_2");
    is(substr($ws, -2), "\x53\xae", "OP_3 OP_CHECKMULTISIG");
    my @pk;
    my $off = 1;
    for (1 .. 3) {
        is(substr($ws, $off, 1), "\x21", "33-byte key push");
        push @pk, substr($ws, $off + 1, 33);
        $off += 34;
    }
    is_deeply([@pk], [sort @pk], "BIP67 (lexicographic) key order");
    like(substr($_, 0, 1), qr/^[\x02\x03]$/, "compressed pubkey prefix") foreach @pk;
    return @pk;
}

# The full derivation chain for the current network's constants.
sub check_net {
    my ($net) = @_;
    my $ws = QBT_LOCK_WITNESS_SCRIPT;
    my @pk = parse_multisig($ws);
    is_deeply([@pk], [sort @{&QBT_LOCK_PUBKEYS}], "$net: witnessScript is built from QBT_LOCK_PUBKEYS");

    my $redeem = QBT_LOCK_REDEEM_SCRIPT;
    is($redeem, "\x00\x20" . sha256($ws), "$net: redeemScript is the P2WSH witness program");
    is(QBT_LOCK_SCRIPTSIG, "\x22" . $redeem, "$net: scriptSig is a single push of the redeemScript");
    is(length(QBT_LOCK_SCRIPTSIG), 35, "$net: scriptSig template length");

    my $spk = QBT_LOCK_SCRIPT;
    is($spk, "\xa9\x14" . hash160($redeem) . "\x87", "$net: P2SH scriptPubKey");

    my $addr = QBT_LOCK_ADDR;
    is($addr, base58check(pack("C", BTC_P2SH_VER) . hash160($redeem)), "$net: Base58Check address");
    is(scriptpubkey_to_btc_address($spk), $addr, "$net: address matches Bitcoin::Address encoding");
    return @pk;
}

# Mainnet (default config)
my @pk = check_net("mainnet");
like(QBT_LOCK_ADDR, qr/^3/, "mainnet address version prefix");

# Testnet and regtest run in subprocesses: the derived constants are state-cached
# per process, so the network cannot be switched after the first call.
foreach my $net (qw(testnet regtest)) {
    my $code = qq{
        use QBitcoin::Config;
        \$config->{$net} = 1;
        use QBitcoin::BlockchainParams;
        print join("|", QBT_LOCK_ADDR, map unpack("H*", \$_),
            join("", \@{&QBT_LOCK_PUBKEYS}),
            QBT_LOCK_WITNESS_SCRIPT, QBT_LOCK_REDEEM_SCRIPT, QBT_LOCK_SCRIPTSIG, QBT_LOCK_SCRIPT), "\\n";
    };
    open(my $fh, '-|', $^X, "-I$Bin/../lib", '-e', $code) or die "cannot run subprocess: $!";
    chomp(my $out = <$fh> // '');
    close($fh);
    is($?, 0, "$net: subprocess succeeded");
    my ($addr, $pubkeys, $ws, $redeem, $scriptsig, $spk) = split /\|/, $out;
    $_ = pack("H*", $_) foreach $pubkeys, $ws, $redeem, $scriptsig, $spk;
    my @pubkeys = unpack("(a33)*", $pubkeys);
    is($ws, "\x52" . join("", map { "\x21" . $_ } sort @pubkeys) . "\x53\xae",
        "$net: witnessScript is built from QBT_LOCK_PUBKEYS");
    is($redeem, "\x00\x20" . sha256($ws), "$net: redeemScript");
    is($scriptsig, "\x22" . $redeem, "$net: scriptSig template");
    is($spk, "\xa9\x14" . hash160($redeem) . "\x87", "$net: scriptPubKey");
    is($addr, base58check("\xc4" . hash160($redeem)), "$net: address");
    like($addr, qr/^2/, "$net: address version prefix");
}

# Regtest dev keys are permanently derivable from fixed strings (tests sign pool
# spends with them); verify the documented derivation contract.
{
    my $code = qq{
        use QBitcoin::Config;
        \$config->{regtest} = 1;
        use QBitcoin::BlockchainParams;
        print unpack("H*", QBT_LOCK_WITNESS_SCRIPT), "\\n";
    };
    open(my $fh, '-|', $^X, "-I$Bin/../lib", '-e', $code) or die "cannot run subprocess: $!";
    chomp(my $ws_hex = <$fh> // '');
    close($fh);
    my $ws = pack("H*", $ws_hex);
    foreach my $op (qw(A B C)) {
        my $pk = Crypt::PK::ECC->new;
        $pk->import_key_raw(sha256("QBTC:REGTEST:LOCK:$op"), 'secp256k1');
        my $pub = $pk->export_key_raw('public_compressed');
        ok(index($ws, "\x21" . $pub) > 0, "regtest dev key $op is in the witnessScript");
    }
}

done_testing();
