package QBitcoin::Coinbase;
use warnings;
use strict;
use feature 'state';

use Scalar::Util qw(weaken refaddr);
use QBitcoin::Accessors qw(new mk_accessors);
use QBitcoin::Log;
use QBitcoin::Const;
use QBitcoin::Config;
use QBitcoin::BlockchainParams;
use QBitcoin::ORM qw(:types dbh find fetch delete_by for_log DEBUG_ORM);
use QBitcoin::Crypto qw(hash160 hash256);
use QBitcoin::Address qw(script_by_pubkey);
use QBitcoin::ProtocolState qw(btc_synced);
use QBitcoin::Script::OpCodes qw(:OPCODES);
use QBitcoin::RedeemScript;
use QBitcoin::ValueUpgraded qw(upgrade_value);
use QBitcoin::Downgrade;
use Bitcoin::Serialized;
use Bitcoin::Transaction;
use Bitcoin::Block;

use constant TABLE => 'coinbase';

use constant FIELDS => {
    btc_block_height => NUMERIC,
    btc_tx_num       => NUMERIC,
    btc_out_num      => NUMERIC, # for upgrade_stop entries: input index of the stop-utxo spend
    btc_tx_hash      => BINARY,
    btc_tx_data      => BINARY,
    merkle_path      => BINARY,
    value            => NUMERIC,
    scripthash       => NUMERIC,
    tx_out           => NUMERIC,
    upgrade_level    => NUMERIC,
    upgrade_stop     => NUMERIC, # 1 for a stop-utxo spend record (TX_TYPE_UPGRADE_STOP payload), 0 for a regular coinbase
};

mk_accessors(keys %{&FIELDS});

my %COINBASE; # just short-live cache for recently produced entries

# upgrade_stop records share the table (and the strict btc ordering) with regular
# coinbases but live in their own key namespace: btc_out_num of a marker is an input
# index and may collide with a burn output of the same btc transaction
sub _cache_key {
    my ($self) = @_; # object or hashref
    return $self->{btc_tx_hash} . $self->{btc_out_num} . ($self->{upgrade_stop} ? "s" : "");
}

sub ensure_btc_block {
    my $self = shift;
    # When upgrade finished, btc_block table may be empty.
    # Ensure a stub btc_block row exists for the FK constraint.
    return unless UPGRADE_FINISHED;
    return if Bitcoin::Block->fetch(height => $self->btc_block_height);
    Bitcoin::Block->create({
        height      => $self->btc_block_height,
        hash        => $self->btc_block_hash,
        time        => 0,
        bits        => 0,
        nonce       => 0,
        version     => 0,
        chainwork   => 0,
        scanned     => 1,
        prev_hash   => undef,
        merkle_root => ZERO_HASH,
    });
}

sub store {
    my $self = shift;
    my $class = ref $self;
    # fetch is more low-level than find and does not create object
    my ($coinbase) = $class->fetch(
        btc_block_height => $self->btc_block_height,
        btc_tx_num       => $self->btc_tx_num,
        btc_out_num      => $self->btc_out_num,
        upgrade_stop     => $self->upgrade_stop ? 1 : 0,
    );
    if ($coinbase) {
        $self->{tx_out} //= $coinbase->{tx_out};
        return;
    }
    $self->ensure_btc_block();
    # upgrade_stop records have no destination output, so no scripthash
    my $scripthash_id = defined($self->scripthash) ? QBitcoin::RedeemScript->store($self->scripthash)->id : undef;
    my $sql = "INSERT INTO `" . TABLE . "` (btc_block_height, btc_tx_num, btc_out_num, btc_tx_hash, btc_tx_data, merkle_path, value, scripthash, tx_out, upgrade_level, upgrade_stop) VALUES (?,?,?,UNHEX(?),UNHEX(?),UNHEX(?),?,?,NULL,?,?)";
    DEBUG_ORM && Debugf("dbi [%s] values [%u,%u,%u,%s,%s,%s,%lu,%s,%u,%u]", $sql, $self->btc_block_height, $self->btc_tx_num, $self->btc_out_num, for_log($self->btc_tx_hash), for_log($self->btc_tx_data), for_log($self->merkle_path), $self->value, $scripthash_id // "null", $self->upgrade_level, $self->upgrade_stop ? 1 : 0);
    my $res = dbh->do($sql, undef, $self->btc_block_height, $self->btc_tx_num, $self->btc_out_num, unpack("H*", $self->btc_tx_hash), unpack("H*", $self->btc_tx_data), unpack("H*", $self->merkle_path), $self->value, $scripthash_id, $self->upgrade_level, $self->upgrade_stop ? 1 : 0);
    $res == 1
        or die "Can't store coinbase " . $self->btc_tx_num . ":" . $self->btc_out_num . ": " . (dbh->errstr // "no error") . "\n";
    if ($self->upgrade_stop) {
        # A new stop record (from the btc scan or received with a TX_TYPE_UPGRADE_STOP
        # transaction from a peer) changes the locally known stop position.
        # Unconfirmed coinbase records at or after the stop can never be confirmed;
        # such records exist if a peer relayed the coinbase before the stop became known
        my $sql_del = "DELETE FROM `" . TABLE . "` WHERE upgrade_stop = 0 AND tx_out IS NULL"
            . " AND (btc_block_height > ? OR (btc_block_height = ? AND btc_tx_num >= ?))";
        dbh->do($sql_del, undef, $self->btc_block_height, $self->btc_block_height, $self->btc_tx_num);
        $class->reset_stop_cache;
    }
}

sub get_value {
    my $self = shift;
    my ($upgrade_level) = @_;
    return upgrade_value($self->value_btc, $upgrade_level);
}

sub create {
    my $class = shift;
    my $args = @_ == 1 ? $_[0] : { @_ };
    my $attr = @_ == 1 ? { %$args } : $args;
    $attr->{value} = upgrade_value($args->{value_btc}, $attr->{upgrade_level} //= 0);
    my $coinbase = $class->new($attr);
    $coinbase->store;
    return $coinbase;
}

sub store_published {
    my $self = shift;
    my ($tx) = @_;

    my $sql = "UPDATE `" . TABLE . "` SET tx_out = ?, upgrade_level = ?, value = ? WHERE btc_tx_hash = UNHEX(?) AND btc_out_num = ? AND upgrade_stop = ? AND tx_out IS NULL";
    DEBUG_ORM && Debugf("dbi [%s] values [%u,%u,%lu,%s,%u,%u]", $sql, $tx->id, $self->upgrade_level, $self->value, for_log($self->btc_tx_hash), $self->btc_out_num, $self->upgrade_stop ? 1 : 0);
    my $res = dbh->do($sql, undef, $tx->id, $self->upgrade_level, $self->value, unpack("H*", $self->btc_tx_hash), $self->btc_out_num, $self->upgrade_stop ? 1 : 0);
    $res == 1
        or die "Can't store coinbase " . for_log($self->btc_tx_hash) . ":" . $self->btc_out_num . " as processed: " . (dbh->errstr // "no error") . "\n";
    $self->reset_stop_confirmed if $self->upgrade_stop;
}

sub value_btc {
    my $self = shift; # object or hashref
    return $self->{value_btc} if defined $self->{value_btc};
    # upgrade_stop record proves an input spend, it carries no value
    # (and its btc_out_num is an input index, not an output one)
    return 0 if $self->{upgrade_stop};
    my $btc_tx_data_obj = Bitcoin::Serialized->new($self->{btc_tx_data});
    my $btc_transaction = Bitcoin::Transaction->deserialize($btc_tx_data_obj);
    my $out = $btc_transaction->out->[$self->{btc_out_num}];
    $self->{value_btc} = $out->{value} if ref($self) eq __PACKAGE__;
    return $out->{value};
}

sub get_new {
    my $class = shift;
    my ($time) = @_;

    # We often generate new block for the same timeslot. In this case we do not need find for new coinbase w/o generated transaction
    state $prev_time = -1;
    return () if $prev_time >= $time;
    $prev_time = $time;

    my ($matched_block) = Bitcoin::Block->find(
        time    => { '<' => $time - COINBASE_CONFIRM_TIME },
        -sortby => 'height DESC',
        -limit  => 1,
    );
    return () unless $matched_block;
    my $max_height = $matched_block->height - COINBASE_CONFIRM_BLOCKS;
    # TODO: move this to QBitcoin::ORM
    my $sql = "SELECT btc_block_height, btc_tx_num, btc_out_num, btc_tx_hash, btc_tx_data, merkle_path, value, s.hash as scripthash";
    $sql .= " FROM `" . $class->TABLE . "` AS t JOIN `" . QBitcoin::RedeemScript->TABLE . "` AS s ON (t.scripthash = s.id)";
    $sql .= " WHERE tx_out IS NULL AND upgrade_stop = 0 AND btc_block_height <= ?";
    my @values = ($max_height);
    # Never generate upgrades at or after the locally known stop-utxo spend; such records
    # should not exist, but a reorg of a branch confirmed before the stop became known
    # may return one to the unconfirmed state
    if (my $first_stop = $class->first_stop) {
        $sql .= " AND (btc_block_height < ? OR (btc_block_height = ? AND btc_tx_num < ?))";
        push @values, $first_stop->{btc_block_height}, $first_stop->{btc_block_height}, $first_stop->{btc_tx_num};
    }
    my $sth = dbh->prepare($sql);
    DEBUG_ORM && Debugf("sql: [%s] values [%s]", $sql, join(",", @values));
    $sth->execute(@values);
    my @coinbase;
    while (my $hash = $sth->fetchrow_hashref()) {
        my $key = _cache_key($hash);
        next if defined($COINBASE{$key}); # transaction for this coinbase already generated (but not stored yet)
        $hash->{value_btc} = value_btc($hash);
        my $coinbase = $class->new($hash);
        $COINBASE{$key} = $coinbase;
        weaken($COINBASE{$key});
        push @coinbase, $coinbase;
    }
    DEBUG_ORM && Debugf("sql: found %u coinbase entries", scalar(@coinbase));
    return @coinbase;
}

# The earliest stored stop-utxo spend record without a published TX_TYPE_UPGRADE_STOP
# transaction, if its btc block is mature enough; the producer builds the marker tx from it
sub get_new_stop {
    my $class = shift;
    my ($time) = @_;

    return undef unless %{&UPGRADE_STOP_UTXO};
    return undef unless $class->first_stop;
    my ($matched_block) = Bitcoin::Block->find(
        time    => { '<' => $time - COINBASE_CONFIRM_TIME },
        -sortby => 'height DESC',
        -limit  => 1,
    );
    return undef unless $matched_block;
    my $max_height = $matched_block->height - COINBASE_CONFIRM_BLOCKS;
    my $sql = "SELECT btc_block_height, btc_tx_num, btc_out_num, btc_tx_hash, btc_tx_data, merkle_path, value, upgrade_level, upgrade_stop";
    $sql .= " FROM `" . $class->TABLE . "` WHERE tx_out IS NULL AND upgrade_stop = 1 AND btc_block_height <= ?";
    $sql .= " ORDER BY btc_block_height ASC, btc_tx_num ASC, btc_out_num ASC LIMIT 1";
    my $sth = dbh->prepare($sql);
    DEBUG_ORM && Debugf("sql: [%s] values [%u]", $sql, $max_height);
    $sth->execute($max_height);
    my $hash = $sth->fetchrow_hashref()
        or return undef;
    my $key = _cache_key($hash);
    return $COINBASE{$key} if defined($COINBASE{$key});
    $hash->{value_btc} = 0;
    my $coinbase = $class->new($hash);
    $COINBASE{$key} = $coinbase;
    weaken($COINBASE{$key});
    return $coinbase;
}

sub DESTROY {
    my $self = shift;
    # weaken() only undefine value but do not delete it, so do it from the object destructor
    my $key = _cache_key($self);
    if (!defined($COINBASE{$key}) || refaddr($self) == refaddr($COINBASE{$key})) {
        delete $COINBASE{$key};
    }
}

# We do not need to build separate singleton cache for coinbase as we do for txo
# b/c coinbase cannot be dropped, only confirmed
# But tx_out and upgrade_level may vary, these are not attributes of the coinbase, but attributes of the transaction
# save them just as links from related transactions
sub load_stored_coinbase {
    my $class = shift;
    my ($tx_id, $tx_hash) = @_;
    # TODO: move this to QBitcoin::ORM
    my $sql = "SELECT btc_block_height, btc_tx_num, btc_out_num, btc_tx_hash, btc_tx_data, merkle_path, value, s.hash as scripthash, upgrade_level, upgrade_stop";
    $sql .= " FROM `" . $class->TABLE . "` AS t LEFT JOIN `" . QBitcoin::RedeemScript->TABLE . "` AS s ON (t.scripthash = s.id)";
    $sql .= " WHERE tx_out = ?";
    my $sth = dbh->prepare($sql);
    DEBUG_ORM && Debugf("sql: [%s] values [%u]", $sql, $tx_id);
    $sth->execute($tx_id);
    my $coinbase;
    if (my $hash = $sth->fetchrow_hashref()) {
        DEBUG_ORM && Debug("orm found coinbase");
        $hash->{tx_out} = $tx_hash;
        $coinbase = $class->new($hash);
    }
    return $coinbase;
}

sub validate {
    my $self = shift;
    my ($btc_block) = Bitcoin::Block->find(hash => $self->btc_block_hash);
    if (!$btc_block || !$btc_block->height) {
        # unset btc_synced() if last btc block older than COINBASE_CONFIRM_TIME
        # otherwise assume this is not correct coinbase.
        # A coinbase needs COINBASE_CONFIRM_TIME after its btc block, so this can happen
        # only if our btc blockchain lags far behind while btc_synced was still set;
        # rejecting (and resetting btc_synced) is a safe reaction here: an unknown btc block
        # is indistinguishable from a fake one, and silently ignoring invalid coinbases
        # would let them go unpunished
        ($btc_block) = Bitcoin::Block->find(-sortby => 'height DESC', -limit => 1);
        if (!$btc_block || $btc_block->time < time() - COINBASE_CONFIRM_TIME) {
            btc_synced(0);
            Warningf("BTC blockchain not synced, can't validate coinbase");
            return -1;
        }
        Warningf("Incorrect coinbase transaction based on unexistent btc block %s", unpack("H*", $self->btc_block_hash));
        return -1;
    }
    if ($btc_block->time < GENESIS_TIME) {
        Warningf("Incorrect coinbase transaction based on early btc block %s time %u", $btc_block->hash_hex, $btc_block->time);
        return -1;
    }
    if ($btc_block->height >= UPGRADE_MAX_BLOCKS) {
        Warningf("Incorrect coinbase transaction based on late btc block %s height %u", $btc_block->hash_hex, $btc_block->height);
        return -1;
    }
    # Check merkle path (but ignore mismatch for produced upgrades)
    if (!$btc_block->check_merkle_path($self->btc_tx_hash, $self->btc_tx_num, $self->merkle_path)) {
        Warningf("Merkle path check failed for btc upgrade transaction %s in block %s",
            unpack("H*", scalar reverse $self->btc_tx_hash), $btc_block->hash_hex);
        return -1;
    }
    $self->{btc_block_height} //= $btc_block->height;

    return 0;
}

sub as_hashref {
    my $self = shift;
    my $value = $self->value; # it's lvalue; prevent convert to float by division
    return {
        btc_block_hash   => unpack("H*", $self->btc_block_hash),
        btc_block_height => $self->btc_block_height+0,
        btc_tx_num       => $self->btc_tx_num+0,
        btc_out_num      => $self->btc_out_num+0,
        btc_tx_data      => unpack("H*", $self->btc_tx_data),
        merkle_path      => unpack("H*", $self->merkle_path),
        value            => $value / DENOMINATOR,
        scripthash       => defined($self->scripthash) ? unpack("H*", $self->scripthash) : undef,
        upgrade_level    => ($self->upgrade_level // 0)+0,
        $self->upgrade_stop ? ( upgrade_stop => 1 ) : (),
    };
}

sub serialize {
    my $self = shift;
    # value and scripthash is matched transaction output and can be fetched from btc_tx_data and btc_out_num
    return
        (varint($self->btc_block_height) // return undef) .
        $self->btc_block_hash .
        (varint($self->btc_tx_num)  // return undef) .
        (varint($self->btc_out_num) // return undef) .
        (varstr($self->btc_tx_data) // return undef) .
        (varstr($self->merkle_path) // return undef);
}

sub compress_ecc_pubkey {
    my ($pubkey) = @_;
    return ("\x02" | (substr($pubkey, -1, 1) & "\x01")) . substr($pubkey, 1, 32);
}

sub get_scripthash {
    my $class = shift;
    my ($tx, $out_num) = @_;
    my $out = $tx->out->[$out_num];
    $out->{open_script} eq QBT_LOCK_SCRIPT
        or return undef;
    # A pool spend pays change back to QBT_LOCK_SCRIPT; that change is already pegged
    # value, not a fresh deposit, and minting for it would double-count the peg. Two
    # stateless signs in the non-witness (txid-committed, SPV-provable) transaction
    # data identify such transactions: an input spending the pool itself (BIP141
    # forces its scriptSig to be exactly QBT_LOCK_SCRIPTSIG), or a strict-format
    # downgrade marker among the outputs (every release carries one). A marker also
    # excludes the transaction paying the deposit script: crafting one next to an own
    # deposit only donates that deposit to the pool.
    if ((grep { ($_->{script} // "") eq QBT_LOCK_SCRIPTSIG } @{$tx->in})
        || QBitcoin::Downgrade->tx_has_downgrade_marker($tx))
    {
        Infof("Skip pool-spend btc tx %s output %u: pool change, not an upgrade", $tx->hash_str, $out_num);
        return undef;
    }
    if (@{$tx->out} > $out_num+1 && substr(my $out_script = $tx->out->[$out_num+1]->{open_script}, 0, 1) eq OP_RETURN) {
        my $len = unpack("C", substr($out_script, 1, 1));
        if (!$len || $len < 20 || $len > 75 || length($out_script) != $len + 2) {
            Warningf("Incorrect QBT upgrade script in tx %s, ignore tx_data", $tx->hash_str);
        }
        else {
            Infof("Upgrade by QBT script in tx %s", $tx->hash_str);
            return substr($out_script, 2);
        }
    }
    # OK, make scripthash by first input of this transaction
    my $in = $tx->in->[0]
        or return undef;
    # Witness (P2WPKH) input address is not proofable by SPV, so we cannot use it for coinbase upgrade
    my $input_script = $in->{script};
    if ($input_script eq "") {
        Warningf("Upgrade from empty script in tx %s", $tx->hash_str);
        return undef;
    }
    # Can we reliable get pubkey or scripthash by the bitcoin input script?
    # In particular, how can we distinguish "push <serialized-script>" for P2SH and "push <pubkeyhash>" for P2PKH without unlock-script?
    # Assume the <serialized-script> is longer than 33 bytes.
    # It's not fully reliable but if somebody tries to deceive this algorithm by creating unusually short script
    # then they will simple lost (burn) their money
    if ($input_script =~ /^([\x41-\x48])(??{ ".{" . ord($1) . "}" })\x21(.{33})\z/s) {
        # it's P2PKH: push 72-bytes signature, push 33-bytes pubkey (compressed)
        Infof("Upgrade from P2PKH script in tx %s", $tx->hash_str);
        return hash160(script_by_pubkey($2));
    }
    elsif ($input_script =~ /^([\x41-\x48])(??{ ".{" . ord($1) . "}" })\x41(.{65})\z/s) {
        # it's P2PKH: push 72-bytes signature, push 65-bytes pubkey (uncompressed): legacy but still possible
        # generate output to the address for compressed pubkey
        Infof("Upgrade from P2PKH script in tx %s", $tx->hash_str);
        return hash160(script_by_pubkey(compress_ecc_pubkey($2)));
    }
    elsif ($input_script =~ /^([\x41-\x48])(??{ ".{" . ord($1) . "}" })\z/s) {
        # it's P2PK, push only 72-bytes DER-encoded signature
        # Pubkey is in the locking script, but we cannot fetch it from the input script.
        # P2PK is deprecated and not allowed by bitcoind anymore
        Warningf("Upgrade from P2PK script in tx %s - unsupported", $tx->hash_str);
        return undef;
    }
    elsif (0) {
        # BTC and QBT scripts are not fully compatible
        # It should work correctly in most cases, but isn't it better deterministic "never" than "almost always"?
        # P2SH script may contains only pushes, and the last one contains the serialized script
        Infof("Upgrade from P2SH in tx %s", $tx->hash_str);
        my $last_push_data;
        while ($input_script ne "") {
            my $first_byte = unpack("C", substr($input_script, 0, 1));
            if ($first_byte > 0 && $first_byte < 0x4c) {
                $last_push_data = substr($input_script, 0, $first_byte+1, "");
                substr($last_push_data, 0, 1, "");
            }
            elsif ($first_byte == OP_PUSHDATA1) {
                my $bytes = unpack("C", substr($input_script, 1, 1));
                $last_push_data = substr($input_script, 0, $bytes+2, "");
                substr($last_push_data, 0, 2, "");
                length($last_push_data) == $bytes or return undef;
            }
            elsif ($first_byte == OP_PUSHDATA2) {
                my $bytes = unpack("v", substr($input_script, 1, 2));
                $last_push_data = substr($input_script, 0, $bytes+3, "");
                substr($last_push_data, 0, 3, "");
                length($last_push_data) == $bytes or return undef;
            }
            else {
                return undef;
            }
        }
        return hash160($last_push_data);
    }
    else {
        Warningf("Upgrade from unknown script in tx %s - unsupported", $tx->hash_str);
        return undef;
    }
    return undef;
}

sub deserialize {
    my $class = shift;
    my ($data, $upgrade_level) = @_;
    my $btc_block_height = $data->get_varint() // return undef;
    my $btc_block_hash   = $data->get(32)      // return undef;
    my $btc_tx_num  = $data->get_varint() // return undef;
    my $btc_out_num = $data->get_varint() // return undef;
    my $btc_tx_data = $data->get_string() // return undef;
    my $merkle_path = $data->get_string() // return undef;
    # Deserialize btc transaction for get upgrade data (value, scripthash)
    my $btc_tx_data_obj = Bitcoin::Serialized->new($btc_tx_data);
    my $transaction = Bitcoin::Transaction->deserialize($btc_tx_data_obj);
    if (!$transaction || $btc_tx_data_obj->length) {
        Warningf("Incorrect btc upgrade transaction data");
        return undef;
    }
    my $out = $transaction->out->[$btc_out_num];
    if (!$out) {
        Warningf("Incorrect btc upgrade transaction data %s, no output %u", $transaction->hash_str, $btc_out_num);
        return undef;
    }
    my $scripthash = $class->get_scripthash($transaction, $btc_out_num);
    if (!$scripthash) {
        Warningf("Incorrect btc upgrade transaction %s output open_script", $transaction->hash_str);
        return undef unless $config->{fake_coinbase};
        $scripthash = ZERO_HASH;
    }

    my $key = $transaction->hash . $btc_out_num;
    return $COINBASE{$key} if defined($COINBASE{$key});
    my $coinbase = $class->new({
        btc_block_height => $btc_block_height,
        btc_block_hash   => $btc_block_hash,
        btc_tx_num       => $btc_tx_num,
        btc_out_num      => $btc_out_num,
        btc_tx_data      => $btc_tx_data,
        btc_tx_hash      => $transaction->hash,
        merkle_path      => $merkle_path,
        upgrade_level    => $upgrade_level,
        value_btc        => $out->{value},
        value            => upgrade_value($out->{value}, $upgrade_level),
        scripthash       => $scripthash,
    });
    $COINBASE{$key} = $coinbase;
    weaken($COINBASE{$key});
    return $coinbase;
}

# Deserialize the payload of a TX_TYPE_UPGRADE_STOP transaction.
# Same wire format as a coinbase payload, but btc_out_num is the index of the
# transaction input which spends one of UPGRADE_STOP_UTXO outputs.
sub deserialize_stop {
    my $class = shift;
    my ($data) = @_;
    my $btc_block_height = $data->get_varint() // return undef;
    my $btc_block_hash   = $data->get(32)      // return undef;
    my $btc_tx_num  = $data->get_varint() // return undef;
    my $btc_in_num  = $data->get_varint() // return undef;
    my $btc_tx_data = $data->get_string() // return undef;
    my $merkle_path = $data->get_string() // return undef;
    my $btc_tx_data_obj = Bitcoin::Serialized->new($btc_tx_data);
    my $transaction = Bitcoin::Transaction->deserialize($btc_tx_data_obj);
    if (!$transaction || $btc_tx_data_obj->length) {
        Warningf("Incorrect btc transaction data in upgrade stop");
        return undef;
    }
    my $in = $transaction->in->[$btc_in_num];
    if (!$in) {
        Warningf("Incorrect btc transaction %s in upgrade stop, no input %u", $transaction->hash_str, $btc_in_num);
        return undef;
    }
    my $utxo = UPGRADE_STOP_UTXO->{$in->{tx_out} . pack("V", $in->{num})};
    if (!$utxo) {
        Warningf("Btc transaction %s input %u in upgrade stop does not spend a stop utxo", $transaction->hash_str, $btc_in_num);
        return undef;
    }
    my $stop = $class->new({
        btc_block_height => $btc_block_height,
        btc_block_hash   => $btc_block_hash,
        btc_tx_num       => $btc_tx_num,
        btc_out_num      => $btc_in_num,
        btc_tx_data      => $btc_tx_data,
        btc_tx_hash      => $transaction->hash,
        merkle_path      => $merkle_path,
        upgrade_level    => 0,
        value_btc        => 0,
        value            => 0,
        scripthash       => undef,
        upgrade_stop     => 1,
    });
    my $key = _cache_key($stop);
    return $COINBASE{$key} if defined($COINBASE{$key});
    $COINBASE{$key} = $stop;
    weaken($COINBASE{$key});
    return $stop;
}

# for serialize loaded blocks
sub btc_block_hash {
    my $self = shift;
    if (!defined $self->{btc_block_hash}) {
        defined($self->{btc_block_height}) or die "BTC block unknown for coinbase\n";
        my ($btc_block) = Bitcoin::Block->find(height => $self->{btc_block_height});
        $self->{btc_block_hash} = $btc_block->hash if $btc_block;
    }
    return $self->{btc_block_hash};
}

sub btc_confirm_time {
    my $self = shift;
    if (!defined $self->{btc_confirm_time}) {
        my ($btc_block) = Bitcoin::Block->find(height => $self->btc_block_height + COINBASE_CONFIRM_BLOCKS);
        return undef unless $btc_block;
        $self->{btc_confirm_time} = $btc_block->time;
        #Debugf("btc_confirm_time for coinbase %s:%u set to %s",
        #    unpack("H*", scalar reverse substr($self->btc_tx_hash, -4)), $self->btc_out_num, $self->{btc_confirm_time});
    }
    return $self->{btc_confirm_time};
}

sub min_tx_time {
    my $self = shift;
    return COINBASE_CONFIRM_TIME + ($self->btc_confirm_time // return undef);
}

sub prev {
    my $self = shift;
    my $h = $self->btc_block_height;
    my $t = $self->btc_tx_num;
    my $o = $self->btc_out_num;
    # The upgrade stop record is ordered before every coinbase of its btc transaction:
    # the whole spending transaction (including its own burn outputs) is after the stop
    # boundary, so the stop is the "prev" for any coinbase of the same transaction
    my $same_tx_cond = $self->upgrade_stop
        ? "upgrade_stop = 1 AND btc_out_num < ?"
        : "(upgrade_stop = 0 AND btc_out_num < ? OR upgrade_stop = 1)";
    my $sql = "SELECT btc_block_height, btc_tx_num, btc_out_num, btc_tx_hash, tx_out, upgrade_stop FROM `" . TABLE . "`"
        . " WHERE (btc_block_height < ? OR (btc_block_height = ? AND btc_tx_num < ?)"
        . " OR (btc_block_height = ? AND btc_tx_num = ? AND $same_tx_cond))"
        . " ORDER BY btc_block_height DESC, btc_tx_num DESC, upgrade_stop ASC, btc_out_num DESC LIMIT 1";
    my $sth = dbh->prepare($sql);
    $sth->execute($h, $h, $t, $h, $t, $o);
    my $prev = $sth->fetchrow_hashref()
        or return undef;
    # Confirmed but not stored yet?
    my $key = _cache_key($prev);
    if (defined($COINBASE{$key})) {
        $prev->{confirmed} = $COINBASE{$key}->tx_out ? 1 : 0;
    }
    else {
        $prev->{confirmed} = $prev->{tx_out} ? 1 : 0;
    }
    return $prev;
}

sub tx_out_str {
    my $self = shift;
    my $tx_out = $self->tx_out // return undef;
    return unpack("H*", substr($tx_out, 0, 4));
}

# The btc position (btc_block_height, btc_tx_num) of the first locally known stop-utxo
# spend, undef if none. It is local knowledge (from the btc scan or a relayed
# TX_TYPE_UPGRADE_STOP transaction), used for the scan gate and the mempool production
# filter; the consensus stop is the confirmed TX_TYPE_UPGRADE_STOP transaction.
# 3-state cache: undef - not computed; 0 - no stop; hashref otherwise.
my $first_stop;

sub first_stop {
    my $class = shift;
    return undef unless %{&UPGRADE_STOP_UTXO};
    if (!defined $first_stop) {
        my $sql = "SELECT btc_block_height, btc_tx_num FROM `" . TABLE . "` WHERE upgrade_stop = 1"
            . " ORDER BY btc_block_height ASC, btc_tx_num ASC LIMIT 1";
        my $sth = dbh->prepare($sql);
        $sth->execute();
        $first_stop = $sth->fetchrow_hashref() // 0;
    }
    return $first_stop || undef;
}

# Called on new stop-utxo spend and on btc reorg (the reorg deletes reverted coinbase
# rows including the upgrade_stop ones, and the new branch is rescanned)
sub reset_stop_cache {
    undef $first_stop;
}

# True if this coinbase record is at or after the locally known stop-utxo spending
# transaction (in btc order), so its upgrade can never be confirmed
sub after_stop {
    my $self = shift;
    my $first_stop = QBitcoin::Coinbase->first_stop
        or return 0;
    return $self->{btc_block_height} > $first_stop->{btc_block_height}
        || ($self->{btc_block_height} == $first_stop->{btc_block_height}
            && $self->{btc_tx_num} >= $first_stop->{btc_tx_num}) ? 1 : 0;
}

# The qbt block height at which the TX_TYPE_UPGRADE_STOP transaction is confirmed in the
# stored blockchain (the database keeps only the best branch), undef if none. Used to
# derive the upgrade_stopped attribute for blocks loaded from the database; in-memory
# blocks get it from validation. In-core (not yet stored) marker does not affect this:
# all stored blocks are below it and therefore not stopped.
# 3-state cache: undef - not computed; -1 - no stop; height otherwise.
my $stop_confirmed_height;

sub stop_confirmed_height {
    my $class = shift;
    return undef unless %{&UPGRADE_STOP_UTXO};
    if (!defined $stop_confirmed_height) {
        my ($height) = dbh->selectrow_array("SELECT MIN(t.block_height) FROM `" . TABLE . "` c"
            . " JOIN `transaction` t ON (c.tx_out = t.id) WHERE c.upgrade_stop = 1");
        $stop_confirmed_height = $height // -1;
    }
    return $stop_confirmed_height < 0 ? undef : $stop_confirmed_height;
}

# Called when the stored marker transaction appears (block with it is stored) or
# disappears (deep reorg deletes stored blocks)
sub reset_stop_confirmed {
    undef $stop_confirmed_height;
}

# Store a stop-utxo spend detected by the btc block scan as an upgrade_stop record
sub add_stop_spend {
    my $class = shift;
    my ($block, $tx_num, $in_num) = @_;
    my $tx = $block->transactions->[$tx_num];
    my $stop = $class->create(
        btc_block_height => $block->height,
        btc_block_hash   => $block->hash,
        btc_tx_num       => $tx_num,
        btc_out_num      => $in_num,
        btc_tx_hash      => $tx->hash,
        btc_tx_data      => $tx->data,
        merkle_path      => $block->merkle_path($tx_num),
        value_btc        => 0,
        scripthash       => undef,
        upgrade_stop     => 1,
    );
    $class->reset_stop_cache;
    return $stop;
}

1;
