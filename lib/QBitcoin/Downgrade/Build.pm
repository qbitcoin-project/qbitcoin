package QBitcoin::Downgrade::Build;
use warnings;
use strict;

# Build (and system-sign) a TX_TYPE_DOWNGRADE transaction. Used by the conversion
# service, which holds the system key (QBT_LOCK) and has already created the BTC
# payment to the user's committed scriptPubKey.
#
# The downgrade transaction:
#   - spends the user's freeze output via the system (IF) branch;
#   - commits (btc_txid, btc_vout, btc_value, scriptpubkey) so the burn can later be
#     proved against the BTC payment (scriptpubkey is copied from the freeze data,
#     so the service cannot redirect the payment);
#   - produces one downgrade output carrying the same reclaim_id, from which the
#     user can reclaim after the time-lock if the burn never appears.
#
# It pins the qbtc branch with heavy weight; the matching burn is generated later,
# permissionlessly, by any node once the BTC payment is confirmed.

use QBitcoin::Log;
use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::Crypto qw(hash160);
use QBitcoin::Downgrade;
use QBitcoin::TXO;
use QBitcoin::Transaction;

# build_downgrade_tx($freeze_txo, system_address => $addr, btc_txid => ..., btc_vout => ..., btc_value => ...)
# Returns the signed (unbroadcast) downgrade transaction, or undef on error.
sub build_downgrade_tx {
    my $class = shift;
    my ($freeze_txo, %args) = @_;

    my $sh = $freeze_txo->scripthash // "";
    my ($reclaim_len, $freeze_script, $out_scripthash);
    if    ($sh eq hash160(QBT_FREEZE_SCRIPT))    { $reclaim_len = 20; $freeze_script = QBT_FREEZE_SCRIPT;    $out_scripthash = hash160(QBT_DOWNGRADE_SCRIPT);    }
    elsif ($sh eq hash160(QBT_FREEZE_PQ_SCRIPT)) { $reclaim_len = 32; $freeze_script = QBT_FREEZE_PQ_SCRIPT; $out_scripthash = hash160(QBT_DOWNGRADE_PQ_SCRIPT); }
    else {
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
    my $tx = QBitcoin::Transaction->new(
        in            => [ { txo => $freeze_txo } ],
        out           => [ $out ],
        fee           => 0,
        tx_type       => TX_TYPE_DOWNGRADE,
        down          => $commit,
        received_time => time(),
    );
    $tx->make_sign_freeze_if($tx->in->[0], $args{system_address}, 0, $freeze_script);
    $tx->calculate_hash;
    return $tx;
}

1;
