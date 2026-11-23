-- The committed btc destination script is not limited by the consensus (only by the size of
-- the freeze output data it is copied from), so the column holds a script of any such length.
-- sqlite does not limit the length of a value and can not change the type of a column,
-- so the table is recreated only to have the same declaration as in the schema.
CREATE TABLE `downgrade_new` (
  tx_id        integer NOT NULL PRIMARY KEY,
  freeze_txid  binary(32)      NOT NULL,
  freeze_vout  int unsigned    NOT NULL,
  btc_txid     binary(32)      NOT NULL,
  btc_vout     int unsigned    NOT NULL,
  btc_value    bigint unsigned NOT NULL,
  scriptpubkey blob            NOT NULL,
  FOREIGN KEY (tx_id) REFERENCES `transaction` (id) ON DELETE CASCADE
);
INSERT INTO `downgrade_new` SELECT tx_id, freeze_txid, freeze_vout, btc_txid, btc_vout, btc_value, scriptpubkey FROM `downgrade`;
DROP TABLE `downgrade`;
ALTER TABLE `downgrade_new` RENAME TO `downgrade`;
