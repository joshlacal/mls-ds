-- Track whether a delivery ACK's signature was cryptographically verified.
ALTER TABLE delivery_acks ADD COLUMN verified BOOLEAN NOT NULL DEFAULT TRUE;
