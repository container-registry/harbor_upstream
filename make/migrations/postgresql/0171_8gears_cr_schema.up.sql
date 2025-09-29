/*
Add new column single_active_replication for replication_policy table to support single_active_replication
*/
ALTER TABLE replication_policy ADD COLUMN IF NOT EXISTS single_active_replication boolean;
