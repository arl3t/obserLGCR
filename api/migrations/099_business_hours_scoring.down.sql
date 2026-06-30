-- 099_business_hours_scoring.down.sql — revierte 099
DROP INDEX IF EXISTS idx_py_holidays_date;
DROP TABLE IF EXISTS py_holidays;
DROP TABLE IF EXISTS business_hours_config;
