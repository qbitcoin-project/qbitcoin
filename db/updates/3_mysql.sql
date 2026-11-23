-- The committed btc destination script is not limited by the consensus (only by the size of
-- the freeze output data it is copied from), so the column holds a script of any such length.
-- A downgrade transaction with a script longer than 64 bytes could not be stored.
ALTER TABLE `downgrade` MODIFY scriptpubkey blob NOT NULL;
