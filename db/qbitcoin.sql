
CREATE TABLE `block` (
  height int unsigned NOT NULL PRIMARY KEY,
  time int unsigned NOT NULL,
  hash binary(32) NOT NULL,
  size int unsigned NOT NULL,
  weight bigint unsigned NOT NULL,
  upgraded bigint unsigned NOT NULL DEFAULT 0,
  downgraded bigint unsigned NOT NULL DEFAULT 0,
  downgrade_pinned bigint unsigned NOT NULL DEFAULT 0,
  reward_fund bigint unsigned NOT NULL DEFAULT 0,
  min_fee bigint unsigned NOT NULL DEFAULT 0,
  prev_hash binary(32) DEFAULT NULL,
  merkle_root binary(32) NOT NULL
);
CREATE UNIQUE INDEX `block_hash` ON `block` (hash);
CREATE INDEX `block_time` ON `block` (time);

CREATE TABLE `transaction` (
  id integer NOT NULL AUTO_INCREMENT PRIMARY KEY, -- "integer" (signed) required for sqlite autoincrement
  hash binary(32) NOT NULL,
  block_height int unsigned NOT NULL,
  block_pos smallint unsigned NOT NULL,
  tx_type smallint unsigned NOT NULL DEFAULT 1,
  token_id integer DEFAULT NULL,
  size int unsigned NOT NULL,
  fee bigint signed NOT NULL,
  FOREIGN KEY (block_height) REFERENCES `block`       (height) ON DELETE CASCADE,
  FOREIGN KEY (token_id)     REFERENCES `transaction` (id)     ON DELETE SET NULL
);
CREATE UNIQUE INDEX `tx_hash` ON `transaction` (hash);
CREATE UNIQUE INDEX `tx_block_height_pos` ON `transaction` (block_height, block_pos);

-- Actually these are qbt addresses
CREATE TABLE `redeem_script` (
  id integer NOT NULL AUTO_INCREMENT PRIMARY KEY,
  hash varbinary(32) NOT NULL,
  script blob NULL
);
CREATE UNIQUE INDEX `redeem_script_hash` ON `redeem_script` (hash);

CREATE TABLE `txo` (
  value      bigint unsigned NOT NULL,
  num        int unsigned NOT NULL,
  tx_in      integer NOT NULL,
  tx_out     integer DEFAULT NULL,
  scripthash integer NOT NULL,
  siglist    blob DEFAULT NULL,
  data       blob NOT NULL DEFAULT '',
  PRIMARY KEY (tx_in, num),
  FOREIGN KEY (tx_in)      REFERENCES `transaction`   (id) ON DELETE CASCADE,
  FOREIGN KEY (tx_out)     REFERENCES `transaction`   (id) ON DELETE SET NULL,
  FOREIGN KEY (scripthash) REFERENCES `redeem_script` (id) ON DELETE RESTRICT
);
CREATE INDEX `tx_out` ON `txo` (tx_out, scripthash);

-- Equivocation evidence of a TX_TYPE_SLASHING transaction (two stake proofs), kept so
-- a stored slashing transaction can be rebuilt from the database
-- (see QBitcoin::Slashing::Stored).
CREATE TABLE `slashing` (
  tx_id      integer NOT NULL PRIMARY KEY,
  timeslot   int unsigned NOT NULL,
  prev_hash1 binary(32) NOT NULL,
  digest1    binary(32) NOT NULL,
  raw1       longblob   NOT NULL,
  prev_hash2 binary(32) NOT NULL,
  digest2    binary(32) NOT NULL,
  raw2       longblob   NOT NULL,
  FOREIGN KEY (tx_id) REFERENCES `transaction` (id) ON DELETE CASCADE
);

-- Commitment of a TX_TYPE_DOWNGRADE: where/how much BTC must be paid. Kept so a
-- stored downgrade transaction can be rebuilt from the database
-- (see QBitcoin::Downgrade::Commitment).
CREATE TABLE `downgrade` (
  tx_id        integer NOT NULL PRIMARY KEY,
  freeze_txid  binary(32)      NOT NULL,  -- qbtc freeze transaction hash
  freeze_vout  int unsigned    NOT NULL,
  btc_txid     binary(32)      NOT NULL,  -- committed BTC funding txid (internal byte order)
  btc_vout     int unsigned    NOT NULL,
  btc_value    bigint unsigned NOT NULL,
  scriptpubkey varbinary(64)   NOT NULL,  -- committed BTC destination scriptPubKey
  FOREIGN KEY (tx_id) REFERENCES `transaction` (id) ON DELETE CASCADE
);

-- BTC SPV proof of the payment for a downgrade. While burn_tx_id IS NULL it is an
-- observed-but-not-yet-burned payment awaiting confirmations; once a burn is built
-- (or received) burn_tx_id points to it, and the row also serves as that burn
-- transaction's proof persistence. The btc_block reference is intentionally NOT a
-- cascade: a BTC reorg is handled explicitly (only pending rows are dropped), so a
-- confirmed burn keeps its proof (mirrors how coinbases are handled).
CREATE TABLE `downgrade_spv` (
  downgrade_tx_id  integer NOT NULL PRIMARY KEY,
  btc_block_height int unsigned DEFAULT NULL,
  btc_block_hash   binary(32) NOT NULL,
  btc_tx_num       smallint unsigned NOT NULL,
  btc_tx_hash      binary(32) NOT NULL,
  merkle_path      blob(512) NOT NULL,
  btc_tx_data      longblob NOT NULL,
  burn_tx_id       integer DEFAULT NULL,
  FOREIGN KEY (downgrade_tx_id) REFERENCES `transaction` (id) ON DELETE CASCADE,
  FOREIGN KEY (burn_tx_id)      REFERENCES `transaction` (id) ON DELETE SET NULL
);

CREATE TABLE `tag` (
  id integer NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tag varchar(64) NOT NULL UNIQUE
);

CREATE TABLE `my_address` (
  address     varchar(255) NOT NULL PRIMARY KEY,
  private_key blob(4096)   DEFAULT NULL, -- WIF, or encrypted with the wallet master key (see QBitcoin::Wallet)
  pubkey      blob(2048)   DEFAULT NULL,
  algo        int unsigned NOT NULL DEFAULT 1,
  staked      int unsigned NOT NULL DEFAULT 0,
  tag_id      integer DEFAULT NULL,
  deleg_pubkeyhash varbinary(32) DEFAULT NULL, -- hash of the delegate staking pubkey for delegated-staking addresses
  FOREIGN KEY (tag_id) REFERENCES `tag` (id) ON DELETE SET NULL
);

-- Long-lived staking keys of a delegate node (see QBitcoin::StakingKey); one key
-- serves any number of delegated-staking addresses and never controls money
CREATE TABLE `staking_key` (
  id          integer NOT NULL AUTO_INCREMENT PRIMARY KEY,
  private_key blob(4096)   NOT NULL, -- WIF, or encrypted with the wallet master key (see QBitcoin::Wallet)
  pubkey      blob(2048)   NOT NULL,
  algo        int unsigned NOT NULL DEFAULT 1
);

-- Addresses delegated to this node for staking (see QBitcoin::Delegation); the
-- owner keys are not ours, so these addresses are separate from my_address and
-- do not count towards the wallet balance
CREATE TABLE `delegation` (
  address          varchar(255) NOT NULL PRIMARY KEY,
  staking_key_id   integer      NOT NULL,
  owner_pubkeyhash varbinary(32) NOT NULL, -- 20 bytes hash160 pre-quantum, 32 bytes hash256 post-quantum
  FOREIGN KEY (staking_key_id) REFERENCES `staking_key` (id) ON DELETE CASCADE
);

CREATE TABLE `btc_block` (
  height int unsigned DEFAULT NULL,
  time int unsigned NOT NULL,
  bits int unsigned NOT NULL,
  nonce int unsigned NOT NULL,
  version int unsigned NOT NULL,
  chainwork double unsigned NOT NULL,
  scanned int unsigned NOT NULL,
  hash binary(32) NOT NULL,
  prev_hash binary(32) DEFAULT NULL,
  merkle_root binary(32) NOT NULL
);
CREATE UNIQUE INDEX `btc_height` ON `btc_block` (height);
CREATE UNIQUE INDEX `btc_hash`   ON `btc_block` (hash);
CREATE        INDEX `scanned`    ON `btc_block` (scanned, height);

-- Regular coinbase upgrades (upgrade_stop = 0, an output to the burn address) and
-- stop-utxo spend records (upgrade_stop = 1, btc_out_num is an input index, no
-- scripthash; a spend of an UPGRADE_STOP_UTXO output which stops the conversion).
-- Both kinds share the strict btc ordering (btc_block_height, btc_tx_num, btc_out_num);
-- a stop record is ordered before every coinbase of its own btc transaction.
CREATE TABLE `coinbase` (
  btc_block_height int unsigned DEFAULT NULL,
  btc_tx_num smallint unsigned DEFAULT NULL,
  btc_out_num smallint unsigned NOT NULL,
  btc_tx_hash binary(32) NOT NULL,
  merkle_path blob(512) NOT NULL, -- 16-level btree with 32-byte (256-bit) hashes
  btc_tx_data longblob NOT NULL, -- or 'blob' for sqlite
  value bigint unsigned NOT NULL,
  scripthash integer DEFAULT NULL,
  tx_out integer DEFAULT NULL,
  upgrade_level integer DEFAULT NULL,
  upgrade_stop smallint unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (btc_tx_hash, btc_out_num, upgrade_stop),
  FOREIGN KEY (btc_block_height) REFERENCES `btc_block`     (height) ON DELETE CASCADE,
  FOREIGN KEY (tx_out)           REFERENCES `transaction`   (id)     ON DELETE SET NULL,
  FOREIGN KEY (scripthash)       REFERENCES `redeem_script` (id)     ON DELETE RESTRICT
);
CREATE INDEX `coinbase_tx_out` ON `coinbase` (tx_out);

CREATE TABLE `peer` (
  type_id smallint unsigned NOT NULL,
  status smallint unsigned NOT NULL DEFAULT 0,
  ip binary(16) NOT NULL,
  port smallint unsigned,
  create_time int unsigned NOT NULL,
  update_time int unsigned NOT NULL,
  software varchar(256),
  hostname varchar(64),
  hostname_verified smallint unsigned NOT NULL DEFAULT 0,
  hostname_check_time int unsigned,
  features bigint unsigned NOT NULL DEFAULT 0,
  ping_min_ms int unsigned,
  ping_avg_ms int unsigned,
  reputation float NOT NULL DEFAULT 0,
  failed_connects int NOT NULL DEFAULT 0,
  last_success_time int unsigned,
  last_fail_time int unsigned,
  hidden smallint unsigned NOT NULL DEFAULT 0,
  pinned smallint unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (type_id, ip)
);
CREATE INDEX `peer_reputation` ON `peer` (reputation);

-- Key-value store for node-local settings (e.g. hashed wallet password)
CREATE TABLE `setting` (
  name  varchar(64)  NOT NULL PRIMARY KEY,
  value varchar(255) NOT NULL
);

CREATE TABLE `version` (
  time timestamp not null DEFAULT CURRENT_TIMESTAMP,
  version int unsigned NOT NULL,
  PRIMARY KEY (version)
);
