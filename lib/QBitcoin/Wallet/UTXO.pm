package QBitcoin::Wallet::UTXO;
use warnings;
use strict;

# In-memory registry of unspent outputs the wallet tracks. Pure container:
# which roles a txo has is decided by the caller (QBitcoin::TXO::My->my_roles
# for the usual add/del, QBitcoin::MyAddress on stake flag change).
# Stored values are QBitcoin::TXO objects, but only their instance methods are
# called here, so this module depends on neither TXO nor MyAddress.
#
# Roles are a bitmask; an output may combine several roles (e.g. MY and
# DELEGATED when the node holds the owner key of an address delegated to it
# for staking):
# - MY:        spendable by a wallet key, counted in the balance;
# - STAKED:    used for staking (an own staked address, or the staked genesis
#              part - see STAKEONLY for whether it is counted in the balance);
# - DELEGATED: delegated to this node for staking; not our money;
# - STAKEONLY: a genesis-reward coin: consensus forbids spending it, so it is
#              never counted in the balance; it provides stake weight (STAKED)
#              once its address is set for staking.

use QBitcoin::Log;

use Exporter qw(import);
our @EXPORT_OK = qw(
    myutxo_add
    myutxo_del
    myutxo_list
    myutxo_all
    myutxo_staked
    myutxo_delegated
    UTXO_MY
    UTXO_STAKED
    UTXO_DELEGATED
    UTXO_STAKEONLY
);

use constant {
    UTXO_MY        => 1,
    UTXO_STAKED    => 2,
    UTXO_DELEGATED => 4,
    UTXO_STAKEONLY => 8,
};

use constant ROLE_NAMES => {
    UTXO_MY()        => "my",
    UTXO_STAKED()    => "staked",
    UTXO_DELEGATED() => "delegated",
    UTXO_STAKEONLY() => "stakeonly",
};

my %UTXO;  # key => [ $txo, $roles ]
my %ROLES; # key => $roles (kept separately so hot queries avoid array derefs)

sub _roles_str {
    my ($roles) = @_;
    return join("+", map { ROLE_NAMES->{$_} } grep { $roles & $_ } sort { $a <=> $b } keys %{ROLE_NAMES()});
}

sub myutxo_add {
    my ($txo, $roles) = @_;
    $roles or return;
    my $key = $txo->key;
    # Roles from different sources (own address, delegation) merge, matching
    # del+add recomputation by my_roles
    $roles |= $ROLES{$key} // 0;
    $UTXO{$key} = $txo;
    $ROLES{$key} = $roles;
    Infof("Add %s UTXO %s:%u %lu coins", _roles_str($roles), $txo->tx_in_str, $txo->num, $txo->value);
}

sub myutxo_del {
    my ($txo) = @_;
    my $key = $txo->key;
    if (defined(my $roles = delete $ROLES{$key})) {
        delete $UTXO{$key};
        Infof("Delete %s UTXO %s:%u %lu coins", _roles_str($roles), $txo->tx_in_str, $txo->num, $txo->value);
    }
}

# Own coins: the wallet balance and spendable-output selection.
# Stake-only (genesis-reward) coins are excluded even when staked: consensus
# forbids spending them, so they are never part of the balance.
sub myutxo_list {
    return map { $UTXO{$_} }
        grep { $ROLES{$_} & (UTXO_MY | UTXO_STAKED) && !($ROLES{$_} & UTXO_STAKEONLY) } keys %ROLES;
}

# Stake sources: own staked coins (including the staked genesis part) plus
# coins delegated to this node
sub myutxo_staked {
    return map { $UTXO{$_} } grep { $ROLES{$_} & (UTXO_STAKED | UTXO_DELEGATED) } keys %ROLES;
}

sub myutxo_delegated {
    return map { $UTXO{$_} } grep { $ROLES{$_} & UTXO_DELEGATED } keys %ROLES;
}

# Every tracked output regardless of roles, for re-rolling on wallet changes
# (stake flag toggle, address removal)
sub myutxo_all {
    return values %UTXO;
}

1;
