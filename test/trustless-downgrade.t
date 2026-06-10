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
my $usr_h256 = hash256($usr_pk);
my $oth_addr = ec_address();
my $oth_pk   = $oth_addr->pubkey;

# Freeze IF branch: system sig + TX_TYPE_DOWNGRADE (system-only, anti-grief).
sub freeze_if { OP_7 . OP_TX_TYPE . OP_EQUALVERIFY . chr(length($_[0])) . $_[0] . OP_CHECKSIG }
# Downgrade-output IF branch: permissionless, only constrains TX_TYPE_BURN.
use constant DOWNGRADE_IF => OP_6 . OP_TX_TYPE . OP_EQUALVERIFY . OP_1;

# Build a reclaim script (mirrors _reclaim_script in Const.pm) for a given IF branch.
sub make_reclaim_script {
    my ($if_branch, $csv, $pq) = @_;
    my $size = $pq ? 32 : 20;
    my $hash = $pq ? OP_HASH256 : OP_HASH160;
    return
        OP_IF . $if_branch . OP_ELSE .
        chr(4) . pack("V", $csv) . OP_CSV . OP_DROP .
        OP_OUTPUTDATA . chr(1) . chr(0) . chr(1) . chr($size) . OP_SUBSTR .
        OP_OVER . $hash . OP_EQUALVERIFY . OP_CHECKSIG .
        OP_ENDIF;
}

# -----------------------------------------------------------------------
# 1. OP_TX_TYPE
# -----------------------------------------------------------------------
{
    my $tx_down = MockTx->new(tx_type => TX_TYPE_DOWNGRADE);
    my $tx_burn = MockTx->new(tx_type => TX_TYPE_BURN);
    my $script  = OP_TX_TYPE . OP_7 . OP_EQUALVERIFY . OP_1;
    ok( script_eval([], $script, $tx_down, 0), "OP_TX_TYPE: DOWNGRADE (7) passes EQUALVERIFY with OP_7");
    ok(!script_eval([], $script, $tx_burn, 0), "OP_TX_TYPE: BURN (6) fails EQUALVERIFY with OP_7");
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
# 4. Freeze IF branch: system-only spend in a TX_TYPE_DOWNGRADE
#    siglist: [sig, "\x01"]  ("\x01" = TRUE => IF branch)
# -----------------------------------------------------------------------
{
    my $script  = make_reclaim_script(freeze_if($sys_pk), DOWNGRADE_FREEZE_CSV);
    my $sd      = "freeze_if_sign_data";
    my $sig     = signature($sd, $sys_addr, CRYPT_ALGO_ECDSA, SIGHASH_ALL);
    my $tx_down = MockTx->new(tx_type => TX_TYPE_DOWNGRADE, sign_data => $sd);
    my $tx_burn = MockTx->new(tx_type => TX_TYPE_BURN,      sign_data => $sd);
    ok( script_eval([$sig, "\x01"], $script, $tx_down, 0), "freeze IF: system sig + TX_TYPE_DOWNGRADE passes");
    ok(!script_eval([$sig, "\x01"], $script, $tx_burn, 0), "freeze IF: TX_TYPE_BURN fails OP_TX_TYPE/EQUALVERIFY");
}

# -----------------------------------------------------------------------
# 5. Downgrade-output IF branch: PERMISSIONLESS spend in a TX_TYPE_BURN
#    siglist: ["\x01"]  (just the IF selector — no signature)
# -----------------------------------------------------------------------
{
    my $script  = make_reclaim_script(DOWNGRADE_IF, DOWNGRADE_OUTPUT_CSV);
    my $tx_burn = MockTx->new(tx_type => TX_TYPE_BURN);
    my $tx_down = MockTx->new(tx_type => TX_TYPE_DOWNGRADE);
    ok( script_eval(["\x01"], $script, $tx_burn, 0), "downgrade-output IF: TX_TYPE_BURN passes with no signature");
    ok(!script_eval(["\x01"], $script, $tx_down, 0), "downgrade-output IF: TX_TYPE_DOWNGRADE fails OP_TX_TYPE/EQUALVERIFY");
}

# -----------------------------------------------------------------------
# 6. ELSE branch (user reclaim, EC) for both freeze and downgrade output.
#    siglist: [sig, pubkey, ""]  ("" = FALSE => ELSE branch)
# -----------------------------------------------------------------------
{
    my $sd      = "reclaim_sign_data";
    my $sig_usr = signature($sd, $usr_addr, CRYPT_ALGO_ECDSA, SIGHASH_ALL);
    my $sig_oth = signature($sd, $oth_addr, CRYPT_ALGO_ECDSA, SIGHASH_ALL);
    my $data    = $usr_h256 . "\x19\x76\xa9\x14" . ("\x11" x 20) . "\x88\xac"; # reclaim_id (32) + dummy scriptPubKey tail
    my $tx      = MockTx->new(tx_type => TX_TYPE_STANDARD, sign_data => $sd, data => $data);

    for my $case (
        [ "freeze",           make_reclaim_script(freeze_if($sys_pk), DOWNGRADE_FREEZE_CSV, 1), DOWNGRADE_FREEZE_SEC ],
        [ "downgrade output", make_reclaim_script(DOWNGRADE_IF,        DOWNGRADE_OUTPUT_CSV, 1), DOWNGRADE_OUTPUT_SEC ],
    ) {
        my ($name, $script, $sec) = @$case;
        ok( script_eval([$sig_usr, $usr_pk, ""], $script, $tx, 0), "$name ELSE: correct user passes");
        ok(!script_eval([$sig_oth, $oth_pk, ""], $script, $tx, 0), "$name ELSE: wrong pubkey fails hash256 check");
        is($tx->in->[0]{min_rel_time}, $sec, "$name ELSE: time-based CSV sets min_rel_time");
        delete $tx->in->[0]{min_rel_time};
    }
}

# -----------------------------------------------------------------------
# 7. Production constants: spend paths of the real freeze/downgrade scripts.
# -----------------------------------------------------------------------
{
    my $sd      = "real_reclaim";
    my $sig_usr = signature($sd, $usr_addr, CRYPT_ALGO_ECDSA, SIGHASH_ALL);
    my $data    = $usr_h256 . ("\x00" x 25);
    my $tx      = MockTx->new(tx_type => TX_TYPE_STANDARD, sign_data => $sd, data => $data);
    ok( script_eval([$sig_usr, $usr_pk, ""], QBT_FREEZE_SCRIPT, $tx, 0),
        "QBT_FREEZE_SCRIPT: user reclaim (ELSE) passes");
    ok( script_eval([$sig_usr, $usr_pk, ""], QBT_DOWNGRADE_SCRIPT, $tx, 0),
        "QBT_DOWNGRADE_SCRIPT: user reclaim (ELSE) passes");

    my $tx_burn = MockTx->new(tx_type => TX_TYPE_BURN, data => $data);
    ok( script_eval(["\x01"], QBT_DOWNGRADE_SCRIPT, $tx_burn, 0),
        "QBT_DOWNGRADE_SCRIPT: permissionless BURN spend passes");
}

# -----------------------------------------------------------------------
# 8. ELSE branch, PQ (hash256 identity, FALCON key) — skip if unavailable.
# -----------------------------------------------------------------------
SKIP: {
    my $pq_addr = eval {
        QBitcoin::MyAddress->new(private_key => wallet_import_format(generate_keypair(CRYPT_ALGO_FALCON)->pk_serialize));
    };
    skip "FALCON (post-quantum) keys unavailable", 2 unless $pq_addr;
    my $pq_pk    = $pq_addr->pubkey;
    my $pq_h256  = hash256($pq_pk);
    my $script   = make_reclaim_script(freeze_if($sys_pk), DOWNGRADE_FREEZE_CSV, 1);
    my $sd       = "freeze_else_pq_sign_data";
    my $sig_pq   = signature($sd, $pq_addr, CRYPT_ALGO_FALCON, SIGHASH_ALL);
    my $data     = $pq_h256 . ("\x00" x 25);
    my $tx       = MockTx->new(tx_type => TX_TYPE_STANDARD, sign_data => $sd, data => $data);
    ok( script_eval([$sig_pq, $pq_pk, ""], $script, $tx, 0), "freeze ELSE (PQ): correct user passes");
    my $bad      = $usr_h160 . ("\x00" x 12) . ("\x00" x 25);  # wrong 32-byte hash
    my $tx_bad   = MockTx->new(tx_type => TX_TYPE_STANDARD, sign_data => $sd, data => $bad);
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
