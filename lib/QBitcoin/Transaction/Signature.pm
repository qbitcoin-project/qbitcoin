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
        if (my $info = QBT_RECLAIM_SCRIPTS->{$scripthash}) {
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

# Sign the system (IF) branch of a freeze script: the downgrade federation spends
# the freeze into a TX_TYPE_DOWNGRADE. The IF branch is a 2-of-3 CHECKMULTISIG over
# QBT_FREEZE_PUBKEYS, so $addresses is an arrayref of the signing federation
# addresses (a plain address object is accepted too). CHECKMULTISIG matches
# signatures against the script keys in order, and the script keys are sorted, so
# the signatures are ordered by their pubkeys; qbtc's CHECKMULTISIG pops no extra
# dummy element. siglist: [ sig, ..., "\x01" ]  ("\x01" = OP_TRUE = IF).
sub make_sign_freeze_if {
    my $self = shift;
    my ($in, $addresses, $input_num, $redeem_script) = @_;

    $in->{txo}->set_redeem_script($redeem_script);
    my $sighash_type = SIGHASH_ALL;
    my $sign_data = $self->sign_data($input_num, $sighash_type);
    my @sig = map  { $_->[1] }
              sort { $a->[0] cmp $b->[0] }
              map  { [ $_->pubkey, signature($sign_data, $_, _sign_alg($_), $sighash_type) ] }
              ref($addresses) eq 'ARRAY' ? @$addresses : ($addresses);
    $in->{siglist} = [ @sig, "\x01" ];
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
