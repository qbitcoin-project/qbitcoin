package QBitcoin::Downgrade;
use warnings;
use strict;

# Trustless downgrade (BTC <- QBTC) payloads and BTC-side validation.
#
# Two transactions carry downgrade data:
#
#   TX_TYPE_DOWNGRADE  - the "commitment": spends the user's freeze output, pins
#       the qbtc branch with heavy weight, and commits where/how much BTC must be
#       paid. Fields: btc_txid, btc_vout, btc_value, scriptpubkey.
#
#   TX_TYPE_BURN       - the "proof": spends the downgrade-tx output and carries a
#       BTC SPV proof that the committed payment really happened, then finalizes
#       the burn. Fields: btc_block_hash, btc_tx_num, merkle_path, btc_tx_data.
#
# The burn reads the commitment from the downgrade-tx it spends, so it only needs
# to carry the proof.
#
# Validation of the BTC payment is deliberately format-agnostic: consensus never
# interprets scriptpubkey, it only byte-compares the committed scriptpubkey with
# the actual BTC output. Address-format knowledge lives at the RPC edge (building
# the freeze) and never in consensus, so new BTC address types need no fork.

use QBitcoin::Accessors qw(new mk_accessors);
use QBitcoin::Log;
use QBitcoin::Const;
use QBitcoin::Crypto qw(hash256);
use QBitcoin::ProtocolState qw(btc_synced);
use Bitcoin::Serialized;
use Bitcoin::Transaction;
use Bitcoin::Block;

mk_accessors(qw(btc_txid btc_vout btc_value scriptpubkey
                btc_block_hash btc_tx_num merkle_path btc_tx_data));

# ---------------------------------------------------------------------------
# Commitment payload (TX_TYPE_DOWNGRADE)
# ---------------------------------------------------------------------------
sub serialize_commitment {
    my $self = shift;
    return
        $self->btc_txid .                          # 32 bytes, internal byte order
        varint($self->btc_vout) .
        pack("Q<", $self->btc_value) .             # satoshis
        varstr($self->scriptpubkey);
}

sub deserialize_commitment {
    my $class = shift;
    my ($data) = @_;
    my $btc_txid     = $data->get(32)       // return undef;
    my $btc_vout     = $data->get_varint()  // return undef;
    my $btc_value    = unpack("Q<", $data->get(8) // return undef);
    my $scriptpubkey = $data->get_string()  // return undef;
    return $class->new({
        btc_txid     => $btc_txid,
        btc_vout     => $btc_vout,
        btc_value    => $btc_value,
        scriptpubkey => $scriptpubkey,
    });
}

# ---------------------------------------------------------------------------
# Proof payload (TX_TYPE_BURN)
# ---------------------------------------------------------------------------
sub serialize_proof {
    my $self = shift;
    return
        $self->btc_block_hash .                    # 32 bytes
        varint($self->btc_tx_num) .
        varstr($self->merkle_path) .
        varstr($self->btc_tx_data);
}

sub deserialize_proof {
    my $class = shift;
    my ($data) = @_;
    my $btc_block_hash = $data->get(32)      // return undef;
    my $btc_tx_num     = $data->get_varint() // return undef;
    my $merkle_path    = $data->get_string() // return undef;
    my $btc_tx_data    = $data->get_string() // return undef;
    return $class->new({
        btc_block_hash => $btc_block_hash,
        btc_tx_num     => $btc_tx_num,
        merkle_path    => $merkle_path,
        btc_tx_data    => $btc_tx_data,
    });
}

# ---------------------------------------------------------------------------
# BTC SPV validation (format-agnostic).
#
# Verifies that the proof in this (burn) record proves a confirmed BTC payment
# matching the given commitment ($commit, a QBitcoin::Downgrade with the
# commitment fields). Returns 0 on success, -1 on failure.
#
# Checks:
#   1. proof tx hash (hash256 of btc_tx_data, no witness) == commit->btc_txid;
#   2. the BTC block is known and at least DOWNGRADE_BTC_CONFIRMS deep;
#   3. the merkle path proves the tx is in that block;
#   4. output[commit->btc_vout].scriptPubKey == commit->scriptpubkey (byte equal);
#   5. output[commit->btc_vout].value >= commit->btc_value.
# ---------------------------------------------------------------------------
sub validate_spv {
    my $self = shift;
    my ($commit) = @_;

    my $btc_tx_hash = hash256($self->btc_tx_data);
    if ($btc_tx_hash ne $commit->btc_txid) {
        Warningf("Burn SPV tx hash %s does not match committed txid %s",
            unpack("H*", scalar reverse $btc_tx_hash),
            unpack("H*", scalar reverse $commit->btc_txid));
        return -1;
    }

    # Locate the BTC block and check it is confirmed deeply enough.
    my ($btc_block) = Bitcoin::Block->find(hash => $self->btc_block_hash);
    if (!$btc_block || !defined $btc_block->height) {
        my ($latest) = Bitcoin::Block->find(-sortby => 'height DESC', -limit => 1);
        if (!$latest || $latest->time < time() - COINBASE_CONFIRM_TIME) {
            btc_synced(0);
            Warningf("BTC blockchain not synced, can't validate downgrade burn");
            return -1;
        }
        Warningf("Burn refers to unknown BTC block %s", unpack("H*", $self->btc_block_hash));
        return -1;
    }
    my ($best_btc) = Bitcoin::Block->find(-sortby => 'height DESC', -limit => 1);
    if (!$best_btc || $btc_block->height + DOWNGRADE_BTC_CONFIRMS > $best_btc->height) {
        Warningf("BTC block %u not deep enough for downgrade burn (need %u confirmations)",
            $btc_block->height, DOWNGRADE_BTC_CONFIRMS);
        return -1;
    }

    if (!$btc_block->check_merkle_path($btc_tx_hash, $self->btc_tx_num, $self->merkle_path)) {
        Warningf("Merkle path check failed for downgrade burn BTC tx %s in block %s",
            unpack("H*", scalar reverse $btc_tx_hash), $btc_block->hash_hex // "");
        return -1;
    }

    my $btc_data_obj = Bitcoin::Serialized->new($self->btc_tx_data);
    my $btc_tx       = Bitcoin::Transaction->deserialize($btc_data_obj);
    unless ($btc_tx && !$btc_data_obj->length) {
        Warningf("Failed to deserialize BTC downgrade transaction");
        return -1;
    }
    my $out = $btc_tx->out->[$commit->btc_vout];
    unless ($out) {
        Warningf("BTC downgrade tx %s has no output %u", $btc_tx->hash_hex, $commit->btc_vout);
        return -1;
    }
    if (($out->{open_script} // "") ne $commit->scriptpubkey) {
        Warningf("BTC downgrade output %u scriptPubKey does not match committed destination", $commit->btc_vout);
        return -1;
    }
    if ($out->{value} < $commit->btc_value) {
        Warningf("BTC downgrade output %u value %u below committed %u",
            $commit->btc_vout, $out->{value}, $commit->btc_value);
        return -1;
    }

    return 0;
}

1;
