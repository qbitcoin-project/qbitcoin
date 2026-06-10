package QBitcoin::Transaction::Signature;
use warnings;
use strict;

use QBitcoin::MyAddress;
use QBitcoin::Delegation;
use QBitcoin::Const;
use QBitcoin::Log;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::Script qw(op_pushdata);
use QBitcoin::Script::Delegation qw(SELECTOR_OWNER SELECTOR_DELEGATE);
use QBitcoin::Crypto qw(signature hash160);
use QBitcoin::RedeemScript;
use Role::Tiny;

# Freeze/downgrade output scripthash -> [redeem_script, reclaim_id length].
# The user-reclaim (ELSE) branch reads its identity (hash160/hash256 of the user
# pubkey) from the leading bytes of the output data. Computed lazily.
my %RECLAIM_SCRIPTS;
sub _reclaim_scripts {
    %RECLAIM_SCRIPTS = (
        hash160(QBT_FREEZE_SCRIPT)    => [ QBT_FREEZE_SCRIPT,    32 ],
        hash160(QBT_DOWNGRADE_SCRIPT) => [ QBT_DOWNGRADE_SCRIPT, 32 ],
    ) unless %RECLAIM_SCRIPTS;
    return \%RECLAIM_SCRIPTS;
}

sub _sign_alg {
    my ($address) = @_;
    my @pk_alg = $address->algo;
    if ($config->{sign_alg}) {
        my %pk_alg = map { $_ => 1 } @pk_alg;
        my ($alg) = grep { $pk_alg{$_} } split(/\s+/, $config->{sign_alg});
        return $alg // $pk_alg[0];
    }
    return $pk_alg[0];
}

# useful links:
# https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
# https://en.bitcoin.it/w/images/en/7/70/Bitcoin_OpCheckSig_InDetail.png
# https://developer.bitcoin.org/devguide/transactions.html
# https://gist.github.com/Sjors/5574485 (ruby)

sub sign_transaction {
    my $self = shift;
    foreach my $num (0 .. $#{$self->in}) {
        my $in = $self->in->[$num];
        my $scripthash = $in->{txo}->scripthash;
        # An address delegated to this node: sign the stake branch of the
        # covenant with the staking key (the owner key is not ours)
        my $delegation;
        if ($self->tx_type == TX_TYPE_STAKE && ($delegation = QBitcoin::Delegation->get_by_hash($scripthash))) {
            $self->make_delegation_sign($in, $delegation, $num);
            next;
        }

        # Freeze / downgrade-output user reclaim (ELSE branch).
        if (my $info = _reclaim_scripts()->{$scripthash}) {
            my ($redeem, $len) = @$info;
            my $reclaim_id = substr($in->{txo}->data // "", 0, $len);
            if (my $address = QBitcoin::MyAddress->get_by_pubkeyhash($reclaim_id)) {
                $self->make_sign_reclaim($in, $address, $num, $redeem);
            }
            else {
                Errf("Can't sign reclaim of %s:%u: no key for reclaim_id %s",
                    $in->{txo}->tx_in_str, $in->{txo}->num, unpack("H*", $reclaim_id));
            }
            next;
        }

        if (my $address = QBitcoin::MyAddress->get_by_hash($scripthash, 0)) {
            $self->make_sign($in, $address, $num);
        }
        else {
            Errf("Can't sign transaction: address for %s:%u is not my, scripthash %s",
                $in->{txo}->tx_in_str, $in->{txo}->num, unpack("H*", $scripthash));
        }
    }
    $self->calculate_hash;
}

# Sign the system (IF) branch of a freeze script: the conversion service spends the
# freeze into a TX_TYPE_DOWNGRADE. siglist: [ sig, "\x01" ]  ("\x01" = OP_TRUE = IF).
# The CHECKSIG in the script is against QBT_LOCK_PUBKEY, so $address must hold the
# system key.
sub make_sign_freeze_if {
    my $self = shift;
    my ($in, $address, $input_num, $redeem_script) = @_;

    $in->{txo}->set_redeem_script($redeem_script);
    my $sign_alg     = _sign_alg($address);
    my $sighash_type = SIGHASH_ALL;
    my $sig = signature($self->sign_data($input_num, $sighash_type), $address, $sign_alg, $sighash_type);
    $in->{siglist} = [ $sig, "\x01" ];
}

# Sign the user-reclaim (ELSE) branch of a freeze or downgrade-output script.
# siglist: [ sig, pubkey, "" ]  ("" = OP_FALSE selects the ELSE branch)
sub make_sign_reclaim {
    my $self = shift;
    my ($in, $address, $input_num, $redeem_script) = @_;

    $in->{txo}->set_redeem_script($redeem_script);
    my $sign_alg     = _sign_alg($address);
    my $sighash_type = SIGHASH_ALL;
    my $sig = signature($self->sign_data($input_num, $sighash_type), $address, $sign_alg, $sighash_type);
    $in->{siglist} = [ $sig, $address->pubkey, "" ];
}

sub make_sign {
    my $self = shift;
    my ($in, $address, $input_num) = @_;

    my $redeem_script = $address->script_by_hash($in->{txo}->scripthash)
        or die "Can't get redeem script by hash " . unpack("H*", $in->{txo}->scripthash);
    my $sign_alg = _sign_alg($address);
    my $sighash_type = SIGHASH_ALL;
    my $sign_data = $self->sign_data($input_num, $sighash_type)
        or die "Can't get sign data for input $input_num";
    my $signature = signature($sign_data, $address, $sign_alg, $sighash_type);
    $in->{txo}->set_redeem_script($redeem_script);
    my $script_type = QBitcoin::RedeemScript->script_type($redeem_script);
    if ($script_type eq "P2PKH") {
        $in->{siglist} = [ $signature, $address->pubkey ];
    }
    elsif ($script_type eq "P2PK") {
        $in->{siglist} = [ $signature ];
    }
    elsif ($script_type eq "DELEGATION") {
        # A delegated-staking address whose owner key is in this wallet
        $in->{siglist} = [ $signature, $address->pubkey, SELECTOR_OWNER ];
    }
}

sub make_delegation_sign {
    my $self = shift;
    my ($in, $delegation, $input_num) = @_;

    my $staking_key = $delegation->staking_key;
    my $sighash_type = SIGHASH_ALL;
    my $sign_data = $self->sign_data($input_num, $sighash_type)
        or die "Can't get sign data for input $input_num";
    my $signature = signature($sign_data, $staking_key, $staking_key->algo, $sighash_type);
    $in->{txo}->set_redeem_script($delegation->redeem_script);
    $in->{siglist} = [ $signature, $staking_key->pubkey, SELECTOR_DELEGATE ];
}

1;
