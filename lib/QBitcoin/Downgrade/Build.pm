package QBitcoin::Downgrade::Build;
use warnings;
use strict;

# Build (and system-sign) a TX_TYPE_DOWNGRADE transaction. Used by the downgrade
# federation members, who hold the freeze keys (2 of the 3 QBT_FREEZE_PUBKEYS sign
# the pin) and have already created the BTC payment to the user's committed
# scriptPubKey.
#
# The downgrade transaction:
#   - spends the user's freeze output via the system (IF) branch;
#   - commits the source freeze output plus (btc_txid, btc_vout, btc_value,
#     scriptpubkey) so the burn can later be proved against the BTC payment
#     (scriptpubkey is copied from the freeze data, so the service cannot redirect
#     the payment);
#   - produces one downgrade output carrying the same reclaim_id, from which the
#     user can reclaim after the time-lock if the burn never appears.
#
# It pins the qbtc branch with heavy weight; the matching burn is generated later,
# permissionlessly, by any node once the BTC payment is confirmed.

use QBitcoin::Log;
use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::Downgrade;
use QBitcoin::TXO;
use QBitcoin::Transaction;

# build_downgrade_unsigned($freeze_txo, btc_txid => ..., btc_vout => ..., btc_value => ...)
# The unsigned downgrade transaction (no siglist, no hash). The construction is
# deterministic - a pure function of the freeze output and the commitment - so
# the federation members build the identical object independently and exchange
# signatures over it. Returns undef on error.
sub build_downgrade_unsigned {
    my $class = shift;
    my ($freeze_txo, %args) = @_;

    my $sh = $freeze_txo->scripthash // "";
    my ($reclaim_len, $out_scripthash) = (32, QBT_DOWNGRADE_SCRIPTHASH);
    unless ($sh eq QBT_FREEZE_SCRIPTHASH) {
        Errf("build_downgrade_tx: input is not a freeze output");
        return undef;
    }
    my $data = $freeze_txo->data // "";
    if (length($data) < $reclaim_len) {
        Errf("build_downgrade_tx: freeze data too short");
        return undef;
    }
    my $reclaim_id   = substr($data, 0, $reclaim_len);
    my $scriptpubkey = substr($data, $reclaim_len);

    my $commit = QBitcoin::Downgrade->new({
        freeze_txid  => $freeze_txo->tx_in,
        freeze_vout  => $freeze_txo->num,
        btc_txid     => $args{btc_txid},
        btc_vout     => $args{btc_vout},
        btc_value    => $args{btc_value},
        scriptpubkey => $scriptpubkey,
    });
    my $out = QBitcoin::TXO->new_txo({
        value      => $freeze_txo->value,
        scripthash => $out_scripthash,
        data       => $reclaim_id,
    });
    return QBitcoin::Transaction->new(
        in            => [ { txo => $freeze_txo } ],
        out           => [ $out ],
        fee           => 0,
        tx_type       => TX_TYPE_DOWNGRADE,
        down          => $commit,
        received_time => time(),
    );
}

# build_downgrade_tx($freeze_txo, system_addresses => [$addr1, $addr2], btc_txid => ..., btc_vout => ..., btc_value => ...)
# Returns the signed (unbroadcast) downgrade transaction, or undef on error.
sub build_downgrade_tx {
    my $class = shift;
    my ($freeze_txo, %args) = @_;

    my $signers = $args{system_addresses};
    unless (ref($signers) eq 'ARRAY' && @$signers) {
        Errf("build_downgrade_tx: system_addresses arrayref is required");
        return undef;
    }
    my $tx = $class->build_downgrade_unsigned($freeze_txo, %args)
        or return undef;
    $tx->make_sign_freeze_if($tx->in->[0], $signers, 0, QBT_FREEZE_SCRIPT);
    $tx->calculate_hash;
    return $tx;
}

1;
