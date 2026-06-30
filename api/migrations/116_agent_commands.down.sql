-- 116_agent_commands.down.sql — revierte 116_agent_commands.sql
DROP INDEX IF EXISTS idx_agent_cmds_host_recent;
DROP INDEX IF EXISTS idx_agent_cmds_host_pending;
DROP TABLE IF EXISTS agent_commands;
