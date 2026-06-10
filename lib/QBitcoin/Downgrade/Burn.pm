package QBitcoin::Downgrade::Burn;
use warnings;
use strict;

# Build burn transactions for downgrade payments confirmed on the BTC chain.
# Called once per block cycle from QBitcoin::Generate. Permissionless: the burn
# spends the downgrade output via the IF branch with no signature; its correctness
# is enforced by the SPV proof (validate_burn -> validate_spv).

use QBitcoin::Log;
use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::Downgrade;
use QBitcoin::Downgrade::Spv;
use QBitcoin::TXO;
use QBitcoin::Transaction;
use Bitcoin::Block;

sub generate_burns {
    my $class = shift;
    my ($time) = @_;
    my $count = 0;
    for my $spv (QBitcoin::Downgrade::Spv->get_new($time)) {
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
    my $redeem = $dg_sh eq QBT_DOWNGRADE_SCRIPTHASH ? QBT_DOWNGRADE_SCRIPT
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

    my $proof = QBitcoin::Downgrade->new({
        btc_block_hash => $spv->btc_block_hash,
        btc_tx_num     => $spv->btc_tx_num,
        merkle_path    => $spv->merkle_path,
        btc_tx_data    => $spv->btc_tx_data,
    });

    my $tx = QBitcoin::Transaction->new(
        in            => [ { txo => $txo, siglist => [ "\x01" ] } ],  # permissionless IF (TRUE selector)
        out           => [],
        fee           => 0,
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

1;
