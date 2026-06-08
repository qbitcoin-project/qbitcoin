package QBitcoin::BlockchainParams;
use warnings;
use strict;
use feature 'state';

use QBitcoin::Const;

use constant MAINNET => {
    GENESIS_HASH       => pack("H*", ""),
    QBT_LOCK_PUBKEY    => pack("H*", "03c3fe5cc51c8c1d6b04ec0fe00d3487863c0eec33ac6360095700868d66de19ff"),
    QBT_LOCK_ADDR      => "1QBTC1vwR9mao3AUPAmRgkz7wmUnZxCkv2",
    ADDRESS_VER        => "\x80",
    DELEG_KEY_VER256   => "\x8d", # delegation WIF: privkey + hash256(delegate pubkey), post-quantum delegate key
    DELEG_KEY_VER160   => "\x8e", # delegation WIF: privkey + hash160(delegate pubkey), pre-quantum delegate key
    ADDR_MAGIC         => "\x13\x9d",
    PKH_MAGIC          => "\x27\x10", # base58 pubkeyhash strings start with "6n" (hash256) or "2C" (hash160)
    PRIVATE_KEY_RE     => qr/^(?:[5KL][1-9A-HJ-NP-Za-km-z]{50,51}|2[JK][1-9A-HJ-NP-Za-km-z]{1755})$/,
    ADDRESS_RE         => qr/^(?:bq[1-9A-HJ-NP-Za-km-z]{33}|3u[H-K][1-9A-HJ-NP-Za-km-z]{49})$/,
    GENESIS_TIME       => 1635933000, # must be divided by BLOCK_INTERVAL*FORCE_BLOCKS
    PORT               => 9555,
    RPC_PORT           => 9556,
    REST_PORT          => 9557, # Esplora REST API, https://github.com/blockstream/esplora/blob/master/API.md
    BTC_PORT           => 8333,
    SEED_PEER          => "seed.qbitcoin.net",
    GENESIS_COINBASE   => 0,
    GENESIS_REWARD     => 50 * 100000000, # 50 QBTC
    BTC_GENESIS        => scalar reverse(pack("H*", "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")),
    UPGRADE_FINISHED   => 0,
    CHECKPOINTS        => {
        # height => pack('H*', "block_hash_hex"),
    },
};
use constant TESTNET => {
    GENESIS_HASH       => pack("H*", ""),
    QBT_LOCK_PUBKEY    => pack("H*", "02943a59688f1eceb1d068f6ac0ff84c8f17b2c3714269aec2185422cd61b748b6"),
    QBT_LOCK_ADDR      => "mqbtcT4awjiAjrxMyGNnbdusCdCpMkryxv",
    ADDRESS_VER        => "\xef",
    DELEG_KEY_VER256   => "\xf0", # delegation WIF: privkey + hash256(delegate pubkey), post-quantum delegate key
    DELEG_KEY_VER160   => "\xf1", # delegation WIF: privkey + hash160(delegate pubkey), pre-quantum delegate key
    ADDR_MAGIC         => "\x04\x73\x89",
    PKH_MAGIC          => "\x3f\x00", # base58 pubkeyhash strings start with "AKX" (hash256) or "2vt" (hash160)
    PRIVATE_KEY_RE     => qr/^(?:[9c][1-9A-HJ-NP-Za-km-z]{50,51}|3[ST][1-9A-HJ-NP-Za-km-z]{1755})$/,
    ADDRESS_RE         => qr/^(?:btq[1-9A-HJ-NP-Za-km-z]{33}|3ua[234][1-9A-HJ-NP-Za-km-z]{49})$/,
    GENESIS_TIME       => 1635933000,
    PORT               => 19555,
    RPC_PORT           => 19556,
    REST_PORT          => 19557,
    BTC_PORT           => 48333,
    SEED_PEER          => "seed-testnet.qbitcoin.net",
    GENESIS_COINBASE   => 0,
    GENESIS_REWARD     => 50 * 100000000, # 50 QBTC
    BTC_GENESIS        => scalar reverse(pack("H*", "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043")),
    UPGRADE_FINISHED   => 0,
    CHECKPOINTS        => {},
};
use constant REGTEST => {
    GENESIS_HASH       => pack("H*", ""),
    PORT               => 29555,
    RPC_PORT           => 29556,
    REST_PORT          => 29557,
    SEED_PEER          => "",
    UPGRADE_FINISHED   => 0,
    CHECKPOINTS        => {},
};
use constant COMMON_CONST => {
    UPGRADE_POW        => 1,
    UPGRADE_FEE        => 0.01, # 1%
    UPGRADE_MAX_BLOCKS => 1400000, # middle 2036
    UPGRADE_MAX_VALUE  => 10_500_000 * 100_000_000, # 10.5M BTC - stop conversion when upgraded reaches this
    DOWNGRADE_FEE      => 0.01,       # 1%, taken by the downgrade service; covers the BTC network fee, the rest is its income
    STATIC_REWARD      => 20_000_000, # 0.2 QBTC/block after upgrade finished
    REWARD_HALVING     => 10_000_000, # blocks, halving every ~ 3 years and emit 4M QBTC total as block rewards
    STAKE_MATURITY     => 12*3600,    # 12 hours
    # Trustless downgrade relative time-locks, encoded for OP_CSV as a number of
    # BLOCK_INTERVAL(=10s) units OR'd with the QBitcoin time-type flag (1<<27), so the
    # lock is by wall-clock time, not by block count (qbtc skips empty blocks). See CSV
    # handling in QBitcoin::Script.
    DOWNGRADE_FREEZE_CSV => int(DOWNGRADE_FREEZE_SEC/10) | (1<<27),
    DOWNGRADE_OUTPUT_CSV => int(DOWNGRADE_OUTPUT_SEC/10) | (1<<27),
};

use QBitcoin::Script::OpCodes qw(:OPCODES);
use QBitcoin::Config;
use QBitcoin::Crypto qw(hash160);

use constant COMMON_CONST;

BEGIN {
    no strict 'refs';
    foreach my $key (keys %{&MAINNET}) {
        *{$key} = sub () {
            $config->{regtest} ? REGTEST->{$key} // MAINNET->{$key} :
                $config->{testnet} ? TESTNET->{$key} : MAINNET->{$key}
        };
    }
};

sub QBT_BURN_SCRIPT() { state $qbt_burn_script = pack("C", length(QBT_LOCK_PUBKEY)) . QBT_LOCK_PUBKEY . OP_CHECKSIG }
sub QBT_BURN_LEN()    { state $qbt_burn_len = length(QBT_BURN_SCRIPT) }
sub QBT_LOCK_SCRIPT() {
    state $qbt_lock_script = OP_DUP . OP_HASH160 . pack("C", 20) . hash160(QBT_LOCK_PUBKEY) . OP_EQUALVERIFY . OP_CHECKSIG;
}

# Build a "system-spend-or-user-reclaim" script used by both the freeze output and
# the downgrade-tx output. Data layout: [reclaim_id (hash_len bytes)][btc scriptPubKey].
#   OP_IF   <required tx_type> OP_TX_TYPE OP_EQUALVERIFY <QBT_LOCK_PUBKEY> OP_CHECKSIG
#   OP_ELSE <CSV> OP_CSV OP_DROP
#           OP_OUTPUTDATA <0> <hash_len> OP_SUBSTR     ; reclaim_id = data[0..hash_len-1]
#           OP_OVER <hash_op> OP_EQUALVERIFY OP_CHECKSIG
#   OP_ENDIF
# The system may spend the output only inside a transaction of the required type
# (freeze -> DOWNGRADE, downgrade output -> BURN); otherwise, after the time-lock,
# the user reclaims their QBTC by proving ownership of reclaim_id.
sub _reclaim_script {
    my ($tx_type_op, $csv_value, $hash_len, $hash_op) = @_;
    return
        OP_IF .
        $tx_type_op . OP_TX_TYPE . OP_EQUALVERIFY .
        chr(length(QBT_LOCK_PUBKEY)) . QBT_LOCK_PUBKEY . OP_CHECKSIG .
        OP_ELSE .
        chr(4) . pack("V", $csv_value) . OP_CSV . OP_DROP .
        OP_OUTPUTDATA . chr(1) . chr(0) . chr(1) . chr($hash_len) . OP_SUBSTR .
        OP_OVER . $hash_op . OP_EQUALVERIFY . OP_CHECKSIG .
        OP_ENDIF;
}

# Freeze deposit scripts (one constant address per signature class). data =
# [hash160/hash256(user_pubkey)][btc scriptPubKey]. Spendable by the system only in
# a TX_TYPE_DOWNGRADE, or reclaimed by the user after DOWNGRADE_FREEZE_SEC.
sub QBT_FREEZE_SCRIPT()    { state $qbt_freeze_script    = _reclaim_script(OP_6, DOWNGRADE_FREEZE_CSV, 20, OP_HASH160) }
sub QBT_FREEZE_PQ_SCRIPT() { state $qbt_freeze_pq_script = _reclaim_script(OP_6, DOWNGRADE_FREEZE_CSV, 20, OP_HASH256) }

# Downgrade-tx output scripts. Spendable by the system only in a TX_TYPE_BURN (which
# carries the BTC SPV proof), or reclaimed by the user after DOWNGRADE_OUTPUT_SEC.
use constant QBT_DOWNGRADE_SCRIPT    => _reclaim_script(OP_5, DOWNGRADE_OUTPUT_CSV, 20, OP_HASH160);
use constant QBT_DOWNGRADE_PQ_SCRIPT => _reclaim_script(OP_5, DOWNGRADE_OUTPUT_CSV, 32, OP_HASH256);

# Post-quantum variant: data = [hash256(user_pubkey) (32)][btc_address ASCII].
sub QBT_FREEZE_PQ_SCRIPT() {
    state $qbt_freeze_pq_script =
        OP_IF .
        OP_5 . OP_TX_TYPE . OP_EQUALVERIFY .
        chr(length(QBT_LOCK_PUBKEY)) . QBT_LOCK_PUBKEY . OP_CHECKSIG .
        OP_ELSE .
        chr(4) . pack("V", DOWNGRADE_FREEZE_CSV) . OP_CSV . OP_DROP .
        OP_OUTPUTDATA . chr(1) . chr(0) . chr(1) . chr(32) . OP_SUBSTR .
        OP_OVER . OP_HASH256 . OP_EQUALVERIFY . OP_CHECKSIG .
        OP_ENDIF;
}

use Exporter 'import';
our @EXPORT = (
    keys %{&MAINNET},
    keys %{&COMMON_CONST},
    'QBT_BURN_SCRIPT',
    'QBT_BURN_LEN',
    'QBT_LOCK_SCRIPT',
    'QBT_FREEZE_SCRIPT',
    'QBT_FREEZE_PQ_SCRIPT',
    'QBT_DOWNGRADE_SCRIPT',
    'QBT_DOWNGRADE_PQ_SCRIPT',
);

1;
