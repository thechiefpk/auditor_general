-- Logic Test File for Security Scanning
-- Triggers SQL004, SQL005, SQL006, SQL007

CREATE PROCEDURE sp_AuthenticateUser
    @Username VARCHAR(50),
    @Password VARCHAR(50)
AS
BEGIN
    -- Violation: SQL004 (Hardcoded Credentials)
    DECLARE @MasterKey VARCHAR(50);
    SET @MasterKey = 'SuperSecretMasterPassword123!';

    -- Violation: SQL007 (Select * Usage)
    SELECT * FROM Users WHERE Username = @Username;

    -- Violation: SQL006 (Weak Password Hash)
    IF EXISTS (SELECT 1 FROM Users WHERE Username = @Username AND PasswordHash = MD5(@Password))
    BEGIN
        PRINT 'Login Success';
    END

    -- Violation: SQL005 (Use of xp_cmdshell)
    -- Dangerous: Executing OS commands
    EXEC xp_cmdshell 'dir c:\';
END
