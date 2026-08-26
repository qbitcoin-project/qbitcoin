package QBitcoin::BlockchainParams;
use warnings;
use strict;
use feature 'state';

use QBitcoin::Const;

# Spending any of these BTC UTXOs stops the btc->qbt conversion: coinbase upgrades are
# not allowed starting from the spending btc transaction (in btc order, including its
# own outputs); burns in earlier transactions of the same block are still converted.
# Keys are "txid:vout" with txid in display (RPC) byte order; compiled to binary prevout keys.
sub _stop_utxo_set {
    return { map {
        my ($txid, $vout) = split /:/;
        scalar(reverse pack("H*", $txid)) . pack("V", $vout) => $_
    } @_ };
}

use constant MAINNET => {
    GENESIS_HASH       => pack("H*", ""),
    # BTC pubkeys of the three federation operators behind the deposit/pool address
    # (2-of-3, see QBT_LOCK_WITNESS_SCRIPT / QBT_LOCK_SCRIPT below); any order here,
    # the witnessScript sorts them (BIP67). Address: 3QBTC3wxgSPUbKLqjZjh6aGwM3yKHWhaLU
    QBT_LOCK_PUBKEYS   => [
        pack("H*", "024ee83659c56ad0663c324cbeaf4cf969ed2c8171af7b5f71afcef472321f22f7"),
        pack("H*", "032a20877b907de2a1a9ee1ce5043f1dd324605a24c64e41663ce8905ac45d2f1c"),
        pack("H*", "026463dbd08255e4c5930d889902cf0b02efba68c0de392c2cfe10e8e4f8e6bac6"),
    ],
    # QBTC pubkeys of the three federation operators signing downgrade (pin)
    # transactions: the freeze-script IF branch is 2-of-3 of them (see _freeze_if
    # below); any order here, the script sorts them. Separate keypairs from
    # QBT_LOCK_PUBKEYS: these sign on the qbtc chain, those on the BTC chain.
    # PLACEHOLDER: publicly derivable keys sha256("QBTC:MAINNET:FREEZE:PLACEHOLDER:{A,B,C}");
    # MUST be replaced with the real operators' keys before launch.
    QBT_FREEZE_PUBKEYS => [
        pack("H*", "02f20842a095bc49c4fcd07b4aa3f2739d788e83d99338d7ec0f50fd18cfe84d64"),
        pack("H*", "0296718866305bbffe8a5033495e35ac3824dfd97a23989fc88ba1dadca3221836"),
        pack("H*", "02809a7885b7c5925bc6fa9bcd0dff35ab1faf0e5f757b2ceee1a8b8c6804a8bb6"),
    ],
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
    BTC_P2PKH_VER      => 0x00,
    BTC_P2SH_VER       => 0x05,
    BTC_BECH32_HRP     => "bc",
    UPGRADE_FINISHED   => 0,
    UPGRADE_STOP_UTXO  => _stop_utxo_set(
        # "txid:vout"
        "6c3efe515b5017c5020e1f20a2c5924fa09e6648cf3eb3858771d2cad7edec45:0", # 0.1 BTC to PK "\x02"x33
        "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098:0", # Coinbase P2PK 50 BTC, block 1
        "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5:0", # Coinbase P2PK 50 BTC, block 2
        "999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644:0", # Coinbase P2PK 50 BTC, block 3
        "44794602bebb5d51996e3c9b6ba9bd72f62bc9308b4eeaf52ca670b0fb9598b4:0", # 1 BTC to P2PKH 1F96aqP38aRb8aVexSUGAh2kiCyjrgoqBh
        "277951bc92bc86ed75ae4baa2ac5e7d1f3ecd2c951819796ad7d04cda431f430:0", #  800 BTC to P2PK block  3307, Feb 2009
        # "6bf2fb101058394e3aa7f79c188cd1967ccf76ac1cebc33c3c7fc510272f98aa:0", # 3233 BTC to P2PK block 40758, Feb 2010
        # "42bd3ac3e78bdaf69c4c020a695cec9fcfc3f9777be531f2fa0aeb23d884db4c:1", #  875 BTC to P2PK block 62373, Jun 2010
    ),
    CHECKPOINTS        => {
        # height => pack('H*', "block_hash_hex"),
    },
};
use constant TESTNET => {
    GENESIS_HASH       => pack("H*", "9a23986048cffb3b5115365cd94fe58441703653e561e0ff89f00c68a424b342"),
    # Address: 2MtQBTCa85CFPFa45Tc19DmuYa3XhfSuD8D
    QBT_LOCK_PUBKEYS   => [
        pack("H*", "032dccf5c2c79a5298dd7e1f1aaf9db35f0b2082c4a7ed599a2fb5bfad5b4e3f36"),
        pack("H*", "03c7f19d0502dd1db33fb5298efbc16848d9c7431ee88fb0fb929205580395599a"),
        pack("H*", "03acebbd33221306e9263cb6d03f7ed33e4bccbc85dc5bef7e49882351650b4909"),
    ],
    # PLACEHOLDER: sha256("QBTC:TESTNET:FREEZE:PLACEHOLDER:{A,B,C}"); replace with the
    # testnet operators' keys before the next split.
    QBT_FREEZE_PUBKEYS => [
        pack("H*", "035549bbafd7b439a9764151ecdb2510d9956845ccabb6ec4661face045a9735af"),
        pack("H*", "02a5fc31f86e612a12cb92077500ad83d7023a659b7dadd8856e926edf75df1e22"),
        pack("H*", "037cee6df7fa27fe46a47a4e941f4288d14c38304c79db96a09fc984c47718e372"),
    ],
    ADDRESS_VER        => "\xef",
    DELEG_KEY_VER256   => "\xf0", # delegation WIF: privkey + hash256(delegate pubkey), post-quantum delegate key
    DELEG_KEY_VER160   => "\xf1", # delegation WIF: privkey + hash160(delegate pubkey), pre-quantum delegate key
    ADDR_MAGIC         => "\x04\x73\x89",
    PKH_MAGIC          => "\x3f\x00", # base58 pubkeyhash strings start with "AKX" (hash256) or "2vt" (hash160)
    PRIVATE_KEY_RE     => qr/^(?:[9c][1-9A-HJ-NP-Za-km-z]{50,51}|3[ST][1-9A-HJ-NP-Za-km-z]{1755})$/,
    ADDRESS_RE         => qr/^(?:btq[1-9A-HJ-NP-Za-km-z]{33}|3ua[234][1-9A-HJ-NP-Za-km-z]{49})$/,
    GENESIS_TIME       => 1784460000, # 2026-07-19 11:20:00
    PORT               => 19555,
    RPC_PORT           => 19556,
    REST_PORT          => 19557,
    BTC_PORT           => 48333,
    SEED_PEER          => "seed-testnet.qbitcoin.net",
    GENESIS_COINBASE   => 0,
    GENESIS_REWARD     => 50 * 100000000, # 50 QBTC
    BTC_GENESIS        => scalar reverse(pack("H*", "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043")),
    BTC_P2PKH_VER      => 0x6F,
    BTC_P2SH_VER       => 0xC4,
    BTC_BECH32_HRP     => "tb",
    UPGRADE_FINISHED   => 0,
    UPGRADE_STOP_UTXO  => _stop_utxo_set(),
    CHECKPOINTS        => {},
};
use constant REGTEST => {
    GENESIS_HASH       => pack("H*", ""),
    # Regtest 2-of-3 lock keys, address 2N43iTdZBtFPzs5PvKkkbw8noqiDMGWrmLQ.
    # Dev keys, intentionally derivable as sha256("QBTC:REGTEST:LOCK:{A,B,C}") so tests
    # can sign pool spends without storing secrets.
    QBT_LOCK_PUBKEYS   => [
        pack("H*", "0257b3c47b272acf97881d3c1f65c122dcbd1098c218dd7a9d612fce02b87c9599"),
        pack("H*", "02a9e30e791334d7cc4ababd3cb6e5795668f654d434e941aa96ee23442643ad07"),
        pack("H*", "03cd91e21e72efff1cbaf0c70837a791c163e7b508f775de47bd7a6bacef3a6c1f"),
    ],
    # Regtest freeze federation dev keys, intentionally derivable as
    # sha256("QBTC:REGTEST:FREEZE:{A,B,C}") so tests can sign downgrade pins.
    QBT_FREEZE_PUBKEYS => [
        pack("H*", "0366c664ba2dde9c8931786e269f0227f96b2ea07c7cf7fe4f887862aa30351817"),
        pack("H*", "0211c906662c581837d270de164e4117d188edfb099248fa68846615ecbee6ad84"),
        pack("H*", "035e2e8ee57e1e110b5b37db3d13a3a00d7cb9610434521a9bcdbe4be5ca131358"),
    ],
    PORT               => 29555,
    RPC_PORT           => 29556,
    REST_PORT          => 29557,
    SEED_PEER          => "",
    BTC_P2PKH_VER      => 0x6F,
    BTC_P2SH_VER       => 0xC4,
    BTC_BECH32_HRP     => "bcrt",
    UPGRADE_FINISHED   => 0,
    UPGRADE_STOP_UTXO  => _stop_utxo_set(
        # block 9 coinbase, the first ever spent satoshi's coins; arbitrary value for regtest
        "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9:0",
    ),
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
use QBitcoin::Crypto qw(hash160 sha256 checksum32);
use Encode::Base58::GMP qw(encode_base58);

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


# The BTC-side system address: btc->qbt upgrade deposits are recognized by an
# output paying QBT_LOCK_SCRIPT, and the same address holds the frozen BTC pool
# the downgrade service pays releases from. It is a P2SH-wrapped P2WSH 2-of-3
# multisig of the federation operators (QBT_LOCK_PUBKEYS):
#   witnessScript = OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG, BIP67 key order
#   redeemScript  = OP_0 <32: sha256(witnessScript)>       (P2WSH witness program)
#   scriptPubKey  = OP_HASH160 <20: hash160(redeemScript)> OP_EQUAL
# BIP141 requires the scriptSig of every spend of such an output to be exactly a
# single push of the redeemScript, so QBT_LOCK_SCRIPTSIG is a deterministic
# 35-byte constant located in the non-witness (txid-committed, SPV-provable) part
# of the spending transaction: it identifies pool spends (releases, fee bumps,
# transfers co-spending a pool input), which must not be counted as upgrade
# deposits even though they pay change back to QBT_LOCK_SCRIPT.
sub QBT_LOCK_WITNESS_SCRIPT() {
    state $qbt_lock_witness_script = do {
        my @pubkeys = @{&QBT_LOCK_PUBKEYS};
        @pubkeys == 3 && !grep(length($_) != 33, @pubkeys)
            or die "QBT_LOCK_PUBKEYS must be three 33-byte compressed pubkeys";
        OP_2 . join("", map { pack("C", 33) . $_ } sort @pubkeys) . OP_3 . OP_CHECKMULTISIG;
    };
}
sub QBT_LOCK_REDEEM_SCRIPT() { state $qbt_lock_redeem = "\x00\x20" . sha256(QBT_LOCK_WITNESS_SCRIPT) }
sub QBT_LOCK_SCRIPTSIG()     { state $qbt_lock_scriptsig = "\x22" . QBT_LOCK_REDEEM_SCRIPT }
sub QBT_LOCK_SCRIPT() {
    state $qbt_lock_script = OP_HASH160 . pack("C", 20) . hash160(QBT_LOCK_REDEEM_SCRIPT) . OP_EQUAL;
}
# Base58Check P2SH address of the lock script - the published deposit address.
sub QBT_LOCK_ADDR() {
    state $qbt_lock_addr = do {
        my $payload = pack("C", BTC_P2SH_VER) . hash160(QBT_LOCK_REDEEM_SCRIPT);
        "" . encode_base58("0x" . unpack("H*", $payload . checksum32($payload)), "bitcoin");
    };
}

# Build a "system-spend-or-user-reclaim" script used by both the freeze output and
# the downgrade-tx output. Data layout: [reclaim_id (hash_len bytes)][btc scriptPubKey].
#   OP_IF   <if_branch>
#   OP_ELSE <CSV> OP_CSV OP_DROP
#           OP_OUTPUTDATA <0> <hash_len> OP_SUBSTR     ; reclaim_id = data[0..hash_len-1]
#           OP_OVER <hash_op> OP_EQUALVERIFY OP_CHECKSIG
#   OP_ENDIF
# The IF branch constrains the system spend to a specific transaction type;
# otherwise, after the time-lock, the user reclaims their QBTC by proving ownership
# of reclaim_id.
sub _reclaim_script {
    my ($if_branch, $csv_value, $hash_len, $hash_op) = @_;
    return
        OP_IF . $if_branch . OP_ELSE .
        chr(4) . pack("V", $csv_value) . OP_CSV . OP_DROP .
        OP_OUTPUTDATA . chr(1) . chr(0) . chr(1) . chr($hash_len) . OP_SUBSTR .
        OP_OVER . $hash_op . OP_EQUALVERIFY . OP_CHECKSIG .
        OP_ENDIF;
}

# Freeze deposit script (one constant address). data = [hash256(user_pubkey)][btc
# scriptPubKey]. reclaim_id is always hash256(pubkey): a single script serves both
# EC and post-quantum reclaim keys (OP_CHECKSIG dispatches on the signature class,
# and the key store indexes pubkeys by both hash160 and hash256). The IF branch is
# spendable only by the downgrade federation - 2 of the 3 QBT_FREEZE_PUBKEYS, keys
# in the script in lexicographic order - and only in a TX_TYPE_DOWNGRADE: grief
# pinning (committing a freeze to a payment that never comes) requires compromising
# two operators, not one. Otherwise the user reclaims after DOWNGRADE_FREEZE_SEC.
# Note: qbtc's OP_CHECKMULTISIG pops no extra dummy element (the bitcoin bug is not
# reproduced), so the siglist is exactly [sig, sig, "\x01"].
sub _freeze_if() {
    state $freeze_if = do {
        my @pubkeys = @{&QBT_FREEZE_PUBKEYS};
        @pubkeys == 3 or die "QBT_FREEZE_PUBKEYS must be three pubkeys";
        OP_7 . OP_TX_TYPE . OP_EQUALVERIFY .
            OP_2 . join("", map { pack("C", length($_)) . $_ } sort @pubkeys) . OP_3 . OP_CHECKMULTISIG;
    };
}
sub QBT_FREEZE_SCRIPT()     { state $qbt_freeze_script = _reclaim_script(_freeze_if(), DOWNGRADE_FREEZE_CSV, 32, OP_HASH256) }
sub QBT_FREEZE_SCRIPTHASH() { state $qbt_freeze_scripthash = hash160(QBT_FREEZE_SCRIPT) }

# Downgrade-tx output script. The IF branch is permissionless: any node may spend
# it in a TX_TYPE_BURN, no signature required. The burn's correctness (that the
# committed BTC payment really happened) is enforced by the SPV proof in
# validate_burn, not by a signature. Otherwise the user reclaims after
# DOWNGRADE_OUTPUT_SEC.
use constant _DOWNGRADE_IF => OP_6 . OP_TX_TYPE . OP_EQUALVERIFY . OP_1;
use constant QBT_DOWNGRADE_SCRIPT     => _reclaim_script(_DOWNGRADE_IF, DOWNGRADE_OUTPUT_CSV, 32, OP_HASH256);
use constant QBT_DOWNGRADE_SCRIPTHASH => hash160(QBT_DOWNGRADE_SCRIPT);

# Freeze/downgrade output scripthash -> [redeem_script, reclaim_id length].
# The user-reclaim (ELSE) branch reads its identity (hash160/hash256 of the user
# pubkey) from the leading bytes of the output data.
sub QBT_RECLAIM_SCRIPTS()   {
    state $reclaim_scripts = {
        QBT_FREEZE_SCRIPTHASH()    => [ QBT_FREEZE_SCRIPT,    32 ],
        QBT_DOWNGRADE_SCRIPTHASH() => [ QBT_DOWNGRADE_SCRIPT, 32 ],
    };
}

use Exporter 'import';
our @EXPORT = (
    keys %{&MAINNET},
    keys %{&COMMON_CONST},
    'QBT_LOCK_WITNESS_SCRIPT',
    'QBT_LOCK_REDEEM_SCRIPT',
    'QBT_LOCK_SCRIPTSIG',
    'QBT_LOCK_SCRIPT',
    'QBT_LOCK_ADDR',
    'QBT_FREEZE_SCRIPT',
    'QBT_FREEZE_SCRIPTHASH',
    'QBT_DOWNGRADE_SCRIPT',
    'QBT_DOWNGRADE_SCRIPTHASH',
    'QBT_RECLAIM_SCRIPTS',
);

1;
