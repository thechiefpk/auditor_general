-- Schema Test File for Compliance Scanning
-- Triggers SQL001, SQL002, SQL003

-- Violation: SQL001 (Unencrypted Sensitive Data)
CREATE TABLE Users (
    Id INT PRIMARY KEY,
    Username VARCHAR(50),
    Password VARCHAR(100), -- Sensitive data in plain text
    SSN CHAR(9),          -- Sensitive data in plain text
    Credit_Card VARCHAR(20) -- Sensitive data in plain text
);

-- Violation: SQL002 (Dangerous Drop Command)
DROP TABLE LegacyUsers;
DROP DATABASE OldProd;

-- Violation: SQL003 (Grant All Privileges)
GRANT ALL ON Users TO 'webapp_user';
