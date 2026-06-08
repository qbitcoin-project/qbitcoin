package QBitcoin::DowngradeData;
use warnings;
use strict;

# Side-table persistence for the trustless-downgrade payload.
#
# A stored transaction is reconstructed from its columns (in/out from the txo
# table) rather than from its raw serialized bytes, so the downgrade payload (the
# commitment for a TX_TYPE_DOWNGRADE, the SPV proof for a TX_TYPE_BURN) is kept
# here, keyed by transaction id, and re-attached to the transaction on load.
#
# The same bytes are also embedded in the transaction serialization (right after
# tx_type, see QBitcoin::Transaction::serialize) and therefore committed to the
# transaction hash; this table just makes the payload available when a stored
# transaction is rebuilt from the database.

use QBitcoin::Accessors qw(new mk_accessors);
use QBitcoin::ORM qw(:types fetch create);

use constant TABLE => 'downgrade';

use constant FIELDS => {
    tx_id   => NUMERIC, # transaction.id of the downgrade or burn transaction
    payload => BINARY,  # serialized commitment (DOWNGRADE) or SPV proof (BURN)
};

use constant PRIMARY_KEY => qw(tx_id);

mk_accessors(keys %{&FIELDS});

1;
