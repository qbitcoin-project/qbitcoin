package QBitcoin::Burn;
use warnings;
use strict;

# Maps a burn transaction (tx_type == TX_TYPE_BURN) to the Bitcoin transaction
# that released the corresponding BTC during a downgrade. This is the reverse
# of the upgrade direction, where QBitcoin::Coinbase records the source BTC txid;
# here a burn (downgrade) records the destination BTC txid, so the QBTC->BTC link
# is traceable on-chain for AML purposes.
#
# Stored in a side table rather than as a column on `transaction` because burn
# transactions are rare relative to the total, so a nullable column there would
# be mostly empty.
#
# The btc_txid is also embedded in the burn transaction's serialization (right
# after tx_type, see QBitcoin::Transaction::serialize) and is therefore committed
# to the transaction hash and signed by the freeze1 key; this table just makes it
# available when a stored transaction is reconstructed from the database.

use QBitcoin::Accessors qw(new mk_accessors);
use QBitcoin::ORM qw(:types fetch create);

use constant TABLE => 'burn_txid';

use constant FIELDS => {
    tx_id    => NUMERIC, # transaction.id of the burn transaction
    btc_txid => BINARY,  # 32 bytes, same byte order as the Bitcoin explorer hex
};

use constant PRIMARY_KEY => qw(tx_id);

mk_accessors(keys %{&FIELDS});

1;
