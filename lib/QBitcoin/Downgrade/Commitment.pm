package QBitcoin::Downgrade::Commitment;
use warnings;
use strict;

# Persistence of a TX_TYPE_DOWNGRADE commitment (where/how much BTC must be paid),
# so a stored downgrade transaction can be rebuilt from the database. Typed columns
# (not a blob): btc_txid, btc_vout, btc_value, scriptpubkey, keyed by transaction id.

use QBitcoin::Accessors qw(new mk_accessors);
use QBitcoin::ORM qw(:types fetch find create);

use constant TABLE => 'downgrade';

use constant FIELDS => {
    tx_id        => NUMERIC, # transaction.id of the downgrade transaction
    btc_txid     => BINARY,  # committed BTC funding txid (internal byte order)
    btc_vout     => NUMERIC,
    btc_value    => NUMERIC,
    scriptpubkey => BINARY,  # committed BTC destination scriptPubKey
};

use constant PRIMARY_KEY => qw(tx_id);

mk_accessors(keys %{&FIELDS});

1;
