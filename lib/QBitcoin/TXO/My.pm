package QBitcoin::TXO::My;
use warnings;
use strict;

# Wallet-facing facade composed into QBitcoin::TXO: joins a txo with the
# wallet addresses, delegations and trustless-downgrade reclaim outputs
# (is_my, my_roles) and delegates the my-utxo bookkeeping to the
# QBitcoin::Wallet::UTXO registry.

use Role::Tiny;

use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::Crypto qw(hash160);
# Call the registry functions fully qualified: Role::Tiny composes all subs
# from the role package into the consumer, so importing them here would turn
# them into QBitcoin::TXO methods
use QBitcoin::MyAddress;
use QBitcoin::Delegation;
use QBitcoin::Wallet::UTXO ();

# Trustless-downgrade reclaim outputs (freeze / downgrade-output scripts) are owned
# not by their scripthash — which is a shared protocol constant — but by the
# reclaim_id = hash256(pubkey) committed in the leading 32 bytes of the output data.
# We treat them as our ordinary UTXOs (balance, listunspent, staking, spend = the
# ELSE-branch reclaim) once their relative CSV time-lock has elapsed. Map each
# reclaim scripthash to that time-lock.
my %RECLAIM_CSV_SEC;
sub _reclaim_csv_sec {
    %RECLAIM_CSV_SEC = (
        hash160(QBT_FREEZE_SCRIPT)    => DOWNGRADE_FREEZE_SEC,
        hash160(QBT_DOWNGRADE_SCRIPT) => DOWNGRADE_OUTPUT_SEC,
    ) unless %RECLAIM_CSV_SEC;
    return \%RECLAIM_CSV_SEC;
}

# The MyAddress that may reclaim this output (by its reclaim_id), or undef when this
# is not a reclaim output whose key we hold.
sub reclaim_address {
    my $self = shift;
    exists _reclaim_csv_sec()->{$self->scripthash // ""}
        or return undef;
    my $reclaim_id = substr($self->data // "", 0, 32);
    length($reclaim_id) == 32 or return undef;
    return QBitcoin::MyAddress->get_by_pubkeyhash($reclaim_id);
}

# For a reclaim output: 1 once the CSV time-lock elapsed (reclaimable as ours), 0
# while still locked, undef when this is not a reclaim output. Maturity is relative
# to the confirming block time of the output: block.time + csv_sec <= now.
sub reclaim_mature {
    my $self = shift;
    my ($now) = @_;
    my $csv_sec = _reclaim_csv_sec()->{$self->scripthash // ""}
        // return undef;
    my $txo_time = QBitcoin::Transaction->txo_time($self)
        // return 0;   # unconfirmed output is not yet reclaimable
    return $txo_time + $csv_sec <= ($now // time()) ? 1 : 0;
}

# A reclaim output still inside its CSV lock: hidden from balance / listunspent /
# staking, as if already spent (the expected path is downgrade+burn → we get BTC;
# reclaim is only a refund backstop if that never happens).
sub is_immature_reclaim {
    my $self = shift;
    my ($now) = @_;
    my $mature = $self->reclaim_mature($now);
    return defined($mature) && !$mature;
}

# Bitmask of QBitcoin::Wallet::UTXO roles for this output; 0 for a foreign one.
# Reclaim outputs are owned via their reclaim_id (all maturities: the CSV lock is
# applied at the point of use via is_immature_reclaim).
sub my_roles {
    my $self = shift;
    my $roles = 0;
    my $my_address = QBitcoin::MyAddress->get_by_hash($self->scripthash, 0) // $self->reclaim_address;
    if ($my_address) {
        $roles |= $my_address->staked ? QBitcoin::Wallet::UTXO::UTXO_STAKED : QBitcoin::Wallet::UTXO::UTXO_MY;
    }
    if (QBitcoin::Delegation->get_by_hash($self->scripthash)) {
        $roles |= QBitcoin::Wallet::UTXO::UTXO_DELEGATED;
    }
    return $roles;
}

sub add_my_utxo {
    my $self = shift;
    QBitcoin::Wallet::UTXO::myutxo_add($self, $self->my_roles);
}

sub del_my_utxo {
    my $self = shift;
    QBitcoin::Wallet::UTXO::myutxo_del($self);
}

sub my_utxo {
    return QBitcoin::Wallet::UTXO::myutxo_list();
}

sub staked_utxo {
    return QBitcoin::Wallet::UTXO::myutxo_staked();
}

sub is_my {
    my $self = shift;
    return !!$self->my_roles;
}

sub is_delegated {
    my $self = shift;
    return !!QBitcoin::Delegation->get_by_hash($self->scripthash);
}

1;
