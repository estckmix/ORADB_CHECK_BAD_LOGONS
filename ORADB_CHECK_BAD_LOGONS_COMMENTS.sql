-- ===========================================================================
-- NAME:        ORADB_CHECK_BAD_LOGONS
-- CREATED:     09-APR-2016
-- BY:          D. RADOICIC
-- VERSION:     3.0
-- DESCRIPTION: Checks the audit tables for invalid logon attempts
-- NOTE:
-- INPUT PARAMETERS:
--      - Entity Name - Passed automatically by alert.pl
--      - 1st Argument Time interval in minutes to scan for bad logons.
--      - 2nd Argument 
--      - 3rd Argument 
--      - AUX CFG file location - optional, Passed automatically by alert.pl
-- ALERT.PL CONFIG FILE SYNTAX:
--   - <SCRIPT_NAME>|1|1|10|20|0|
--      - position 1 = script name
--      - position 2 = type of script (1 = oracle sql, 2 = OS, 3 = PERL)
--      - position 3 = off/on (0 = off / 1 = on)
--      - position 4 = 1st argument
--      - position 5 = 2nd argument
--      - position 6 = 3rd argument
-- AUX_CFG.cfg CONFIG FILE SYNTAX:
--    <SCRIPT_NAME>|<ENTITY_NAME>|<CONTEXT>|<VAL1>|<VAL2>|...|<VAL15>
--      - position 1 = script name
--      - position 2 = Entity name/ID, wildcard with *
--      - position 3 = alert.pl context, wildcard with *
--      - aux_cfg_col1 = 
--      - aux_cfg_col2 = 
--      ...
--      - aux_cfg_col15 = 
-- MODIFICATION HISTORY
-- DATE         AUTHOR              DESCRIPTION
-- -----------  ------------------  ---------------------------------------------
-- 09-APR-2016  D. RADOICIC         Initial Version
-- ===============================================================================

-- Enable server output for debugging or informational messages
set serveroutput on

-- Turn off variable substitution verification for cleaner output
set verify off

-- Declare and initialize a variable to store RAC status
var racstat number;
exec :racstat := 0;

-- Declare a variable to capture the input time interval (in minutes)
var minuteInterval number;
exec select &1 into :minuteInterval from dual;

-- Check if the database is a RAC (Real Application Cluster) primary node
begin
  select count(*) into :racstat
  from v$instance
  where instance_number = (select min(a.instance_number)
                            from gv$instance a, v$thread b
                            where a.instance_role = 'PRIMARY_INSTANCE' -- database role
                            and a.status = 'OPEN' -- instance status
                            and b.status = 'OPEN' -- thread status
                            and a.thread# = b.thread#);
end;
/

-- Declare the main block to process invalid logon attempts
declare

  -- Define alert type for log identification
  ALERT_TYPE VARCHAR2(64) := 'ORADB_CHECK_BAD_LOGONS';

  -- Define a cursor to query invalid logon attempts from the audit table
  CURSOR session_cur IS
    select a.username, a.userhost, a.terminal, a.action_name, a.returncode, min(a.timestamp) mts, count(*) cnt
    from sys.dba_audit_session a
    where a.timestamp > current_timestamp - :minuteInterval/1440 -- filter by time interval
      and a.action_name = 'LOGON' -- filter for logon attempts
      and a.returncode <> 0 -- filter for unsuccessful attempts
    group by a.username, a.userhost, a.terminal, a.action_name, a.returncode;

  -- Initialize variables to track record counts and DBA status
  nRecords INTEGER := 0;
  isDBA INTEGER := 0;

begin

  -- Proceed only if the current instance is a RAC primary node
  if :racstat = 1 then

    -- Loop through each record in the cursor
    for session_r in session_cur loop

      -- Set flag indicating records exist
      nRecords := 1;

      -- Check if the unsuccessful attempt is due to account lockout (ORA-28000)
      if (session_r.returncode = 28000) then 
        select count(*) into isDBA 
        from dba_role_privs 
        where granted_role = 'DBA' 
          and grantee = session_r.username;
      end if;

      -- Output warning messages for specific conditions:
      -- 1. ORA-28000 (lockout) but not a DBA account
      -- 2. ORA-1017 (invalid credentials) with more than 2 attempts
      if ((session_r.returncode = 28000 and isDBA = 0) or 
          (session_r.returncode = 1017 and session_r.cnt > 2)) then

        dbms_output.put_line(
          'RDBA WARNING UNSUCCESSFUL LOGON ATTEMPT - ' ||
          ' USERNAME: ' || session_r.username ||
          ' USERHOST: ' || session_r.userhost ||
          ' TERMINAL: ' || session_r.terminal ||
          ' TIMESTAMP: ' || to_char(session_r.mts, 'DD-MON-YYYY HH24:MI:SS') ||
          ' ACTION_NAME: ' || session_r.action_name ||
          ' RETURNCODE: ' || session_r.returncode ||
          ' COUNT: ' || session_r.cnt
        );

      end if;

    end loop;

    -- If no records were found, output a message
    if (nRecords = 0) then
      dbms_output.put_line('No Alert Conditions for: ' || ALERT_TYPE);
    end if;

  else
    -- If not on a RAC primary node, output a quiet exit message
    dbms_output.put_line('RACSTAT: ' || ALERT_TYPE || ': Quietly Exitting. Not on RAC Primary Node.');
  end if; -- if RACSTAT

  -- Exception handling block
  exception
    when others then
      raise;
      dbms_output.put_line('RDBA ALERT: ' || ALERT_TYPE || ' FAILED ' || sqlerrm);

end;
/

-- Output a completion message
select
   'Script complete at ' || to_char(sysdate, 'DD-MON-YYYY HH24:MI:SS') "COMPLETE_MSG"
from dual;
