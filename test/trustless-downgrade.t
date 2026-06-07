#! /usr/bin/env perl
use warnings;
use strict;

use FindBin '$Bin';
use lib ("$Bin/../lib", "$Bin/lib");

use Test::More;

use QBitcoin::Config;
use QBitcoin::Const;
use QBitcoin::BlockchainParams;
use QBitcoin::Script qw(script_eval op_pushdata);
use QBitcoin::Script::OpCodes qw(:OPCODES);
use QBitcoin::Crypto qw(signature hash160 hash256 generate_keypair);
use QBitcoin::Address qw(wallet_import_format);
use QBitcoin::MyAddress;

$config->{debug}   = 0;
$config->{regtest} = 1;

# -----------------------------------------------------------------------
# Keypairs
# -----------------------------------------------------------------------
sub ec_address {
    QBitcoin::MyAddress->new(private_key => wallet_import_format(generate_keypair(CRYPT_ALGO_ECDSA)->pk_serialize));
}
my $sys_addr = ec_address();
my $sys_pk   = $sys_addr->pubkey;
my $usr_addr = ec_address();
my $usr_pk   = $usr_addr->pubkey;
my $usr_h160 = hash160($usr_pk);
my $oth_addr = ec_address();
my $oth_pk   = $oth_addr->pubkey;

# -----------------------------------------------------------------------
# Freeze script builder (mirrors QBT_FREEZE_SCRIPT / QBT_FREEZE_PQ_SCRIPT in
# Const.pm but with a test system pubkey so the IF branch can be exercised).
# -----------------------------------------------------------------------
sub make_freeze_script {
    my ($system_pubkey, $pq) = @_;
    my $size = $pq ? 32 : 20;
    my $hash = $pq ? OP_HASH256 : OP_HASH160;
    return
        OP_IF .
        OP_5 . OP_TX_TYPE . OP_EQUALVERIFY .                       # tx_type == TX_TYPE_BURN
        chr(length($system_pubkey)) . $system_pubkey . OP_CHECKSIG .
        OP_ELSE .
        chr(4) . pack("V", DOWNGRADE_FREEZE_CSV) . OP_CSV . OP_DROP .
        OP_OUTPUTDATA . chr(1) . chr(0) . chr(1) . chr($size) . OP_SUBSTR .
        OP_OVER . $hash . OP_EQUALVERIFY . OP_CHECKSIG .
        OP_ENDIF;
}

# -----------------------------------------------------------------------
# 1. OP_TX_TYPE
# -----------------------------------------------------------------------
{
    my $tx_burn = MockTx->new(tx_type => TX_TYPE_BURN);
    my $tx_std  = MockTx->new(tx_type => TX_TYPE_STANDARD);
    my $script  = OP_TX_TYPE . OP_5 . OP_EQUALVERIFY . OP_1;
    ok( script_eval([], $script, $tx_burn, 0), "OP_TX_TYPE: BURN (5) passes EQUALVERIFY with OP_5");
    ok(!script_eval([], $script, $tx_std,  0), "OP_TX_TYPE: STANDARD (1) fails EQUALVERIFY with OP_5");
}

# -----------------------------------------------------------------------
# 2. OP_OUTPUTDATA
# -----------------------------------------------------------------------
{
    my $data     = "\xde\xad\xbe\xef" x 5;
    my $tx_match = MockTx->new(tx_type => TX_TYPE_STANDARD, data => $data);
    my $tx_other = MockTx->new(tx_type => TX_TYPE_STANDARD, data => "\x00" x 20);
    my $script   = op_pushdata($data) . OP_OUTPUTDATA . OP_EQUALVERIFY . OP_1;
    ok( script_eval([], $script, $tx_match, 0), "OP_OUTPUTDATA: matching data passes");
    ok(!script_eval([], $script, $tx_other, 0), "OP_OUTPUTDATA: mismatched data fails");
}

# -----------------------------------------------------------------------
# 3. OP_SUBSTR  (stack: str begin size -> substr)
# -----------------------------------------------------------------------
{
    my $str     = "Hello, World!";  # 13 bytes
    my $s_hello = OP_SUBSTR . op_pushdata("Hello") . OP_EQUALVERIFY . OP_1;
    ok( script_eval([$str, "\x00", "\x05"], $s_hello, "", 0), "OP_SUBSTR: bytes 0..4 -> 'Hello'");
    ok(!script_eval([$str, "\x00", "\x0e"], $s_hello, "", 0), "OP_SUBSTR: size overflow (0+14>13) fails");
    ok(!script_eval([$str, "\x00", "\x81"], $s_hello, "", 0), "OP_SUBSTR: negative size (-1) fails");
}

# -----------------------------------------------------------------------
# 4. Freeze IF branch (system spends, only in a TX_TYPE_BURN)
#    siglist: [sig, "\x01"]  ("\x01" = TRUE => IF branch)
# -----------------------------------------------------------------------
{
    my $script  = make_freeze_script($sys_pk);
    my $sd       = "freeze_if_sign_data";
    my $sig      = signature($sd, $sys_addr, CRYPT_ALGO_ECDSA, SIGHASH_ALL);
    my $tx_burn  = MockTx->new(tx_type => TX_TYPE_BURN,     sign_data => $sd);
    my $tx_std   = MockTx->new(tx_type => TX_TYPE_STANDARD, sign_data => $sd);
    ok( script_eval([$sig, "\x01"], $script, $tx_burn, 0), "freeze IF: system sig + TX_TYPE_BURN passes");
    ok(!script_eval([$sig, "\x01"], $script, $tx_std,  0), "freeze IF: non-BURN tx fails OP_TX_TYPE/EQUALVERIFY");
}

# -----------------------------------------------------------------------
# 5. Freeze ELSE branch, EC (user reclaim after CSV)
#    siglist: [sig, pubkey, ""]  ("" = FALSE => ELSE branch)
# -----------------------------------------------------------------------
{
    my $script  = make_freeze_script($sys_pk);
    my $sd       = "freeze_else_sign_data";
    my $sig_usr  = signature($sd, $usr_addr, CRYPT_ALGO_ECDSA, SIGHASH_ALL);
    my $sig_oth  = signature($sd, $oth_addr, CRYPT_ALGO_ECDSA, SIGHASH_ALL);
    my $data     = $usr_h160 . "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf";
    my $tx       = MockTx->new(tx_type => TX_TYPE_STANDARD, sign_data => $sd, data => $data);
    ok( script_eval([$sig_usr, $usr_pk, ""], $script, $tx, 0), "freeze ELSE (EC): correct user passes");
    ok(!script_eval([$sig_oth, $oth_pk, ""], $script, $tx, 0), "freeze ELSE (EC): wrong pubkey fails hash160 check");
    is($tx->in->[0]{min_rel_time}, DOWNGRADE_FREEZE_SEC, "freeze ELSE: time-based CSV sets min_rel_time to 48h");
}

# -----------------------------------------------------------------------
# 6. The production QBT_FREEZE_SCRIPT (real system key) ELSE branch
#    must accept the user reclaim path (sanity that the constant matches).
# -----------------------------------------------------------------------
{
    my $sd      = "real_freeze_reclaim";
    my $sig_usr = signature($sd, $usr_addr, CRYPT_ALGO_ECDSA, SIGHASH_ALL);
    my $data    = $usr_h160 . "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf";
    my $tx      = MockTx->new(tx_type => TX_TYPE_STANDARD, sign_data => $sd, data => $data);
    ok( script_eval([$sig_usr, $usr_pk, ""], QBT_FREEZE_SCRIPT, $tx, 0),
        "QBT_FREEZE_SCRIPT: user reclaim (ELSE) passes");
}

# -----------------------------------------------------------------------
# 7. Freeze ELSE branch, PQ (hash256 identity, FALCON key) — skip if FALCON
#    is unavailable in this build.
# -----------------------------------------------------------------------
SKIP: {
    my $pq_addr = eval {
        QBitcoin::MyAddress->new(private_key => wallet_import_format(generate_keypair(CRYPT_ALGO_FALCON)->pk_serialize));
    };
    skip "FALCON (post-quantum) keys unavailable", 2 unless $pq_addr;
    my $pq_pk    = $pq_addr->pubkey;
    my $pq_h256  = hash256($pq_pk);
    my $script   = make_freeze_script($sys_pk, 1);
    my $sd       = "freeze_else_pq_sign_data";
    my $sig_pq   = signature($sd, $pq_addr, CRYPT_ALGO_FALCON, SIGHASH_ALL);
    my $data     = $pq_h256 . "bc1qexampleexampleexampleexample";
    my $tx       = MockTx->new(tx_type => TX_TYPE_STANDARD, sign_data => $sd, data => $data);
    ok( script_eval([$sig_pq, $pq_pk, ""], $script, $tx, 0), "freeze ELSE (PQ): correct user passes");
    my $bad = $usr_h160 . ("\x00" x 12) . "bc1qexampleexampleexampleexample"; # wrong 32-byte hash
    my $tx_bad = MockTx->new(tx_type => TX_TYPE_STANDARD, sign_data => $sd, data => $bad);
    ok(!script_eval([$sig_pq, $pq_pk, ""], $script, $tx_bad, 0), "freeze ELSE (PQ): wrong hash256 fails");
}

done_testing();

# -----------------------------------------------------------------------
# Mock transaction objects for script evaluation
# -----------------------------------------------------------------------
package MockTxO;
sub new  { bless { data => $_[1] }, $_[0] }
sub data { $_[0]->{data} }

package MockTx;
# tx_type   => TX_TYPE_* constant
# sign_data => binary string used for signature verification
# data      => data field of in[0].txo (used by OP_OUTPUTDATA)
sub new {
    my ($class, %args) = @_;
    return bless {
        tx_type   => $args{tx_type},
        sign_data => $args{sign_data} // "",
        in        => [{ txo => MockTxO->new($args{data} // ""), min_rel_block_height => -1 }],
    }, $class;
}
sub tx_type   { $_[0]->{tx_type}   }
sub sign_data { $_[0]->{sign_data} }
sub in        { $_[0]->{in}        }

1;
