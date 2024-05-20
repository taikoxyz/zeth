// Raiko
// Copyright (c) 2024 Taiko Labs
// Licensed and distributed under either of
//   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
//   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
// at your option. This file may not be copied, modified, or distributed except according to those terms.

//! # Raiko Task Manager
//!
//! At the moment (Apr '24) proving requires a significant amount of time
//! and maintaining a connection with a potentially external party.
//!
//! By design Raiko is stateless, it prepares inputs and forward to the various proof systems.
//! However some proving backend like Risc0's Bonsai are also stateless,
//! and only accepts proofs and return result.
//! Hence to handle crashes, networking losses and restarts, we need to persist
//! the status of proof requests, task submitted, proof received, proof forwarded.
//!
//! In the diagram:
//!              _____________          ______________             _______________
//! Taiko L2 -> | Taiko-geth | ======> | Raiko-host  | =========> | Raiko-guests |
//!             | Taiko-reth |         |             |            |     Risc0    |
//!             |____________|         |_____________|            |     SGX      |
//!                                                               |     SP1      |
//!                                                               |______________|
//!                                                                _____________________________
//!                                                    =========> |        Prover Networks     |
//!                                                               |        Risc0's Bonsai      |
//!                                                               |  Succinct's Prover Network |
//!                                                               |____________________________|
//!                                                               _________________________
//!                                                    =========> |       Raiko-dist      |
//!                                                               |    Distributed Risc0  |
//!                                                               |    Distributed SP1    |
//!                                                               |_______________________|
//!
//! We would position Raiko task manager either before Raiko-host or after Raiko-host.
//!
//! ## Implementation
//!
//! The task manager is a set of tables and KV-stores.
//! - Keys for table joins are prefixed with id
//! - KV-stores for (almost) immutable data
//! - KV-store for large inputs and indistinguishable from random proofs
//! - Tables for tasks and their metadata.
//!
//!  __________________________
//! | metadata                |
//! |_________________________| A simple KV-store with the DB version for migration/upgrade detection.
//! | Key             | Value | Future version may add new fields, without breaking older versions.
//! |_________________|_______|
//! | task_db_version | 0     |
//! |_________________|_______|
//!
//! ________________________
//! | Proof systems        |
//! |______________________| A map: ID -> proof systems
//! | id_proofsys | Desc   |
//! |_____________|________|
//! | 0           | Risc0  | (0 for Risc0 and 1 for SP1 is intentional)
//! | 1           | SP1    |
//! | 2           | SGX    |
//! |_____________|________|
//!
//!  _________________________________________________
//! | Task Status code                               |
//! |________________________________________________|
//! | id_status   | Desc                             |
//! |_____________|__________________________________|
//! |     0       | Success                          |
//! |  1000       | Registered                       |
//! |  2000       | Work-in-progress                 |
//! |             |                                  |
//! | -1000       | Proof failure (prover - generic) |
//! | -1100       | Proof failure (OOM)              |
//! |             |                                  |
//! | -2000       | Network failure                  |
//! |             |                                  |
//! | -3000       | Cancelled                        |
//! | -3100       | Cancelled (never started)        |
//! | -3200       | Cancelled (aborted)              |
//! | -3210       | Cancellation in progress         | (Yes -3210 is intentional ;))
//! |             |                                  |
//! | -4000       | Invalid or unsupported block     |
//! |             |                                  |
//! | -9999       | Unspecified failure reason       |
//! |_____________|__________________________________|
//!
//! Rationale:
//! - Convention, failures use negative status code.
//! - We leave space for new status codes
//! - -X000 status code are for generic failures segregated by failures:
//!   on the networking side, the prover side or trying to prove an invalid block.
//!
//!   A catchall -9999 error code is provided if a failure is not due to
//!   either the network, the prover or the requester invalid block.
//!   They should not exist in the DB and a proper analysis
//!   and eventually status code should be assigned.
//!
//!  ________________________________________________________________________________________________
//! | Tasks metadata                                                                                 |
//! |________________________________________________________________________________________________|
//! | id_task | chain_id | block_number | blockhash | parent_hash | state_root | # of txs | gas_used |
//! |_________|__________|______________|___________|_____________|____________|__________|__________|
//!  ____________________________________
//! | Task queue                        |
//! |___________________________________|
//! | id_task | blockhash | id_proofsys |
//! |_________|___________|_____________|
//!  ______________________________________
//! | Task payloads                       |
//! |_____________________________________|
//! | id_task | inputs (serialized)       |
//! |_________|___________________________|
//!  _____________________________________
//! | Task requests                      |
//! |____________________________________|
//! | id_task | id_submitter | timestamp |
//! |_________|______________|___________|
//!  ___________________________________________________________________________________
//! | Task progress trail                                                              |
//! |__________________________________________________________________________________|
//! | id_task | third_party            | id_status               | timestamp           |
//! |_________|________________________|_________________________|_____________________|
//! |  101    | 'Based Proposer"       |  1000 (Registered)      | 2024-01-01 00:00:01 |
//! |  101    | 'A Prover Network'     |  2000 (WIP)             | 2024-01-01 00:00:01 |
//! |  101    | 'A Prover Network'     | -2000 (Network failure) | 2024-01-01 00:02:00 |
//! |  101    | 'Proof in the Pudding' |  2000 (WIP)             | 2024-01-01 00:02:30 |
//!·|  101    | 'Proof in the Pudding' |     0 (Success)         | 2024-01-01 01:02:30 |
//!
//! Rationale:
//! - payloads are very large and warrant a dedicated table, with pruning
//! - metadata is useful to audit block building and prover efficiency
//! - Due to failures and retries, we may submit the same task to multiple fulfillers
//!   or retry with the same fulfiller so we keep an audit trail of events.
//!
//! ____________________________
//! | Proof cache               | A map: ID -> proof
//! |___________________________|
//! | id_task  | proof_value    |
//! |__________|________________|  A Groth16 proof is 2G₁+1G₂ elements
//! | 0        | 0xabcd...6789  |  On BN254: 2*(2*32)+1*(2*2*32) = 256 bytes
//! | 1        | 0x1234...cdef  |
//! | ...      | ...            |  A SGX proof is ...
//! |__________|________________|  A Stark proof (not wrapped in Groth16) would be several kilobytes
//!
//! Do we need pruning?
//!   There are 60s * 60min * 24h * 30j = 2592000s in a month
//!   dividing by 12, that's 216000 Ethereum slots.
//!   Assuming 1kB of proofs per block (Stark-to-Groth16 Risc0 & SP1 + SGX, SGX size to be verified)
//!   That's only 216MB per month.

// Imports
// ----------------------------------------------------------------
use rusqlite::Error as SqlError;
use std::io::{Error as IOError, ErrorKind as IOErrorKind};

use std::fs::File;
use std::path::Path;

use raiko_primitives::{BlockNumber, ChainId, B256};

use rusqlite::{named_params, Statement, MappedRows};
use rusqlite::{Connection, OpenFlags};

use chrono::{DateTime, Utc};
use num_enum::{IntoPrimitive, FromPrimitive};

// Types
// ----------------------------------------------------------------

#[derive(PartialEq, Debug)]
pub enum TaskManagerError {
    IOError(IOErrorKind),
    SqlError(String),
}

impl From<IOError> for TaskManagerError {
    fn from(error: IOError) -> TaskManagerError {
        TaskManagerError::IOError(error.kind())
    }
}

impl From<SqlError> for TaskManagerError {
    fn from(error: SqlError) -> TaskManagerError {
        TaskManagerError::SqlError(error.to_string())
    }
}

#[derive(Debug)]
pub struct TaskDb {
    conn: Connection,
}

#[derive(Debug)]
pub struct TaskManager<'db> {
    enqueue_task: Statement<'db>,
    update_task_progress: Statement<'db>,
    get_task_proof: Statement<'db>,
    get_task_proving_status: Statement<'db>,
    get_tasks_unfinished: Statement<'db>,
    get_db_size: Statement<'db>,
}

#[derive(Debug, Copy, Clone)]
pub enum TaskProofsys {
    Risc0 = 0,
    SP1 = 1,
    SGX = 2,
}

#[allow(non_camel_case_types)]
#[rustfmt::skip]
#[derive(PartialEq, Debug, Copy, Clone, IntoPrimitive, FromPrimitive)]
#[repr(i32)]
pub enum TaskStatus {
    Success                   =     0,
    Registered                =  1000,
    WorkInProgress            =  2000,
    ProofFailure_Generic      = -1000,
    ProofFailure_OutOfMemory  = -1100,
    NetworkFailure            = -2000,
    Cancelled                 = -3000,
    Cancelled_NeverStarted    = -3100,
    Cancelled_Aborted         = -3200,
    CancellationInProgress    = -3210,
    InvalidOrUnsupportedBlock = -4000,
    UnspecifiedFailureReason  = -9999,
    #[num_enum(default)]
    SqlDbCorruption           = -99999,
}

// Implementation
// ----------------------------------------------------------------

impl TaskDb {
    fn open(path: &Path) -> Result<Connection, TaskManagerError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        Ok(conn)
    }

    fn create(path: &Path) -> Result<Connection, TaskManagerError> {
        let _file = File::options()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)?;

        let conn = Self::open(path)?;
        Self::create_tables(&conn)?;
        Self::create_views(&conn)?;

        Ok(conn)
    }

    /// Open an existing TaskDb database at "path"
    /// If a database does not exist at the path, one is created.
    pub fn open_or_create(path: &Path) -> Result<Self, TaskManagerError> {
        let conn = if path.exists() {
            Self::open(path)
        } else {
            Self::create(path)
        }?;
        Ok(Self { conn })
    }

    // SQL
    // ----------------------------------------------------------------

    fn create_tables(conn: &Connection) -> Result<(), TaskManagerError> {
        // Change the task_db_version if backward compatibility is broken
        // and introduce a migration on DB opening ... if conserving history is important.
        conn.execute_batch(
            r#"
            -- Metadata and mappings
            -----------------------------------------------

            CREATE TABLE metadata(
                key BLOB UNIQUE NOT NULL PRIMARY KEY,
                value BLOB
            );

            INSERT INTO
                metadata(key, value)
            VALUES
                ('task_db_version', 0);

            CREATE TABLE proofsys(
                id_proofsys INTEGER UNIQUE NOT NULL PRIMARY KEY,
                desc TEXT NOT NULL
            );

            INSERT INTO
                proofsys(id_proofsys, desc)
            VALUES
                (0, 'Risc0'),
                (1, 'SP1'),
                (2, 'SGX');

            CREATE TABLE status_codes(
                id_status INTEGER UNIQUE NOT NULL PRIMARY KEY,
                desc TEXT NOT NULL
            );

            INSERT INTO
                status_codes(id_status, desc)
            VALUES
                (    0, 'Success'),
                ( 1000, 'Registered'),
                ( 2000, 'Work-in-progress'),
                (-1000, 'Proof failure (generic)'),
                (-1100, 'Proof failure (Out-Of-Memory)'),
                (-2000, 'Network failure'),
                (-3000, 'Cancelled'),
                (-3100, 'Cancelled (never started)'),
                (-3200, 'Cancelled (aborted)'),
                (-3210, 'Cancellation in progress'),
                (-4000, 'Invalid or unsupported block'),
                (-9999, 'Unspecified failure reason');

            -- Data
            -----------------------------------------------

            -- Different blockchains might have the same blockhash in case of a fork
            -- for example Ethereum and Ethereum Classic.
            -- As "GuestInput" refers to ChainID, the proving task would be different.
            CREATE TABLE blocks(
                chain_id INTEGER NOT NULL,
                blockhash BLOB NOT NULL,
                block_number INTEGER NOT NULL,
                parent_hash BLOB NOT NULL,
                state_root BLOB NOT NULL,
                num_transactions INTEGER NOT NULL,
                gas_used INTEGER NOT NULL,
                PRIMARY KEY (chain_id, blockhash)
            );

            -- Notes:
            --   1. a blockhash may appear as many times as there are prover backends.
            --   2. For query speed over (chain_id, blockhash, id_proofsys)
            --      there is no need to create an index as the UNIQUE constraint
            --      has an implied index, see:
            --      - https://sqlite.org/lang_createtable.html#uniqueconst
            --      - https://www.sqlite.org/fileformat2.html#representation_of_sql_indices
            CREATE TABLE tasks(
                id_task INTEGER UNIQUE NOT NULL PRIMARY KEY,
                chain_id INTEGER NOT NULL,
                blockhash BLOB NOT NULL,
                id_proofsys INTEGER NOT NULL,
                FOREIGN KEY(chain_id, blockhash) REFERENCES blocks(chain_id, blockhash)
                FOREIGN KEY(id_proofsys) REFERENCES proofsys(id_proofsys)
                UNIQUE (chain_id, blockhash, id_proofsys)
            );

            -- Payloads will be very large, just the block would be 1.77MB on L1 in Jan 2024,
            --   https://ethresear.ch/t/on-block-sizes-gas-limits-and-scalability/18444
            -- mandating ideally a separated high-performance KV-store to reduce IO.
            -- This is without EIP-4844 blobs and the extra input for zkVMs.
            CREATE TABLE task_payloads(
                id_task INTEGER UNIQUE NOT NULL PRIMARY KEY,
                payload BLOB NOT NULL,
                FOREIGN KEY(id_task) REFERENCES tasks(id_task)
            );

            -- Proofs might also be large, so we isolate them in a dedicated table
            CREATE TABLE task_proofs(
                id_task INTEGER UNIQUE NOT NULL PRIMARY KEY,
                proof BLOB NOT NULL,
                FOREIGN KEY(id_task) REFERENCES tasks(id_task)
            );

            CREATE TABLE thirdparties(
                id_thirdparty INTEGER UNIQUE NOT NULL PRIMARY KEY,
                thirdparty_desc TEXT UNIQUE NOT NULL
            );

            CREATE TABLE task_status(
                id_task INTEGER NOT NULL,
                id_thirdparty INTEGER,
                id_status INTEGER NOT NULL,
                timestamp TIMESTAMP DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
                FOREIGN KEY(id_task) REFERENCES tasks(id_task)
                FOREIGN KEY(id_thirdparty) REFERENCES thirdparties(id_thirdparty)
                FOREIGN KEY(id_status) REFERENCES status_codes(id_status)
            );

            "#)?;

        Ok(())
    }

    fn create_views(conn: &Connection) -> Result<(), TaskManagerError> {
        // By convention, views will use an action verb as name.
        conn.execute_batch(
            r#"
            CREATE VIEW enqueue_task AS
                SELECT
                    t.id_task,
                    t.chain_id,
                    t.blockhash,
                    t.id_proofsys,
                    ts.id_status,
                    ts.id_thirdparty AS submitter,
                    t3p.thirdparty_desc,
                    b.block_number,
                    b.parent_hash,
                    b.state_root,
                    b.num_transactions,
                    b.gas_used,
                    tpl.payload
                FROM
                    tasks t
                    LEFT JOIN
                        blocks b on (
                            b.chain_id = t.chain_id
                            AND b.blockhash = t.blockhash
                        )
                    LEFT JOIN
                        task_status ts on ts.id_task = t.id_task
                    LEFT JOIN
                        task_payloads tpl on tpl.id_task = t.id_task
                    LEFT JOIN
                        thirdparties t3p on t3p.id_thirdparty = ts.id_thirdparty;

            CREATE VIEW update_task_progress AS
                SELECT
                    t.id_task,
                    t.chain_id,
                    t.blockhash,
                    t.id_proofsys,
                    ts.id_status,
                    ts.id_thirdparty AS fulfiller,
                    tpf.proof
                FROM
                    tasks t
                    LEFT JOIN
                        task_status ts on ts.id_task = t.id_task
                    LEFT JOIN
                        task_proofs tpf on tpf.id_task = t.id_task;
            "#)?;

        Ok(())
    }

    /// Set a tracer to debug SQL execution
    /// for example:
    ///   db.set_tracer(Some(|stmt| println!("sqlite:\n-------\n{}\n=======", stmt)));
    #[cfg(test)]
    pub fn set_tracer(&mut self, trace_fn: Option<fn(_: &str)>) {
        self.conn.trace(trace_fn);
    }

    pub fn manage<'db>(&'db self) -> Result<TaskManager<'db>, TaskManagerError> {
        // To update all the tables with the task_id assigned by Sqlite
        // we require row IDs for the tasks table
        // and we use last_insert_rowid() which is not reentrant and need a transaction lock
        // and store them in a temporary table, configured to be in-memory.
        //
        // Alternative approaches considered:
        // 1. Sqlite does not support variables (because it's embedded and significantly less overhead than other SQL "Client-Server" DBs).
        // 2. using AUTOINCREMENT and/or the sqlite_sequence table
        //		- sqlite recommends not using AUTOINCREMENT for performance
        //        https://www.sqlite.org/autoinc.html
        // 3. INSERT INTO ... RETURNING nested in a WITH clause (CTE / Common Table Expression)
        // 		- Sqlite can only do RETURNING to the application, it cannot be nested in another query or diverted to another table
        // 		  https://sqlite.org/lang_returning.html#limitations_and_caveats
        // 4. CREATE TEMPORARY TABLE AS with an INSERT INTO ... RETURNING nested
        // 		- Same limitation AND CREATE TABLEAS seems to only support SELECT statements (but if we could nest RETURNING we can workaround that
        // 		  https://www.sqlite.org/lang_createtable.html#create_table_as_select_statements
        //
        // Hence we have to use row IDs and last_insert_rowid()
        //
        // Furthermore we use a view and an INSTEAD OF trigger to update the tables,
        // the alternative being
        //
        // 5. Direct insert into tables
        //		This does not work as SQLite `execute` and `prepare`
        //      only process the first statement.
        //
        // And lastly, we need the view and trigger to be temporary because
        // otherwise they can't access the temporary table:
        //   6. https://sqlite.org/forum/info/4f998eeec510bceee69404541e5c9ca0a301868d59ec7c3486ecb8084309bba1
        //      "Triggers in any schema other than temp may only access objects in their own schema. However, triggers in temp may access any object by name, even cross-schema."

        let conn = &self.conn;
        conn.execute_batch(
            r#"
            -- PRAGMA temp_store = 'MEMORY';

            CREATE TEMPORARY TABLE temp.current_task(id_task INTEGER);

            CREATE TEMPORARY TRIGGER enqueue_task_insert_trigger
                INSTEAD OF INSERT ON enqueue_task
                BEGIN
                    INSERT INTO blocks(chain_id, blockhash, block_number, parent_hash, state_root, num_transactions, gas_used)
                        VALUES (new.chain_id, new.blockhash, new.block_number, new.parent_hash, new.state_root, new.num_transactions, new.gas_used);

                    INSERT INTO tasks(chain_id, blockhash, id_proofsys)
                        VALUES (new.chain_id, new.blockhash, new.id_proofsys);

                    INSERT INTO current_task
                        SELECT id_task FROM tasks
                        WHERE rowid = last_insert_rowid()
                        LIMIT 1;

                    INSERT INTO task_payloads(id_task, payload)
                        SELECT tmp.id_task, new.payload
                        FROM current_task tmp
                        LIMIT 1;

                    INSERT OR IGNORE INTO thirdparties(thirdparty_desc)
                        VALUES (new.submitter);

                    -- Tasks are initialized at status 1000 - registered
                    -- timestamp is auto-filled with datetime('now'), see its field definition
                    INSERT INTO task_status(id_task, id_thirdparty, id_status)
                        SELECT tmp.id_task, t3p.id_thirdparty, 1000
                        FROM current_task tmp
                        JOIN thirdparties t3p
                        WHERE t3p.thirdparty_desc = new.submitter
                        LIMIT 1;

                    DELETE FROM current_task;
                END;

            CREATE TEMPORARY TRIGGER update_task_progress_trigger
                INSTEAD OF INSERT ON update_task_progress
                BEGIN
                    INSERT INTO current_task
                        SELECT id_task
                        FROM tasks
                        WHERE 1=1
                            AND chain_id = new.chain_id
                            AND blockhash = new.blockhash
                            AND id_proofsys = new.id_proofsys
                        LIMIT 1;

                    -- If fulfiller is NULL, due to IGNORE and the NOT NULL requirement,
                    -- table will be left as-is.
                    INSERT OR IGNORE INTO thirdparties(thirdparty_desc)
                        VALUES (new.fulfiller);

                    -- timestamp is auto-filled with datetime('now'), see its field definition
                    INSERT INTO task_status(id_task, id_thirdparty, id_status)
                        SELECT tmp.id_task, t3p.id_thirdparty, new.id_status
                        FROM current_task tmp
                        LEFT JOIN thirdparties t3p
                            -- fulfiller can be NULL, for example
                            -- for tasks Cancelled before they were ever sent to a prover.
                            ON t3p.thirdparty_desc = new.fulfiller
                        LIMIT 1;

                    INSERT OR REPLACE INTO task_proofs
                        SELECT id_task, new.proof
                        FROM current_task
                        WHERE new.proof IS NOT NULL
                        LIMIT 1;

                    DELETE FROM current_task;
                END;
            "#)?;

        let enqueue_task = conn.prepare(
            "
            INSERT INTO enqueue_task(
                    chain_id, blockhash, id_proofsys, submitter,
                    block_number, parent_hash, state_root, num_transactions, gas_used,
                    payload)
                VALUES (
                    :chain_id, :blockhash, :id_proofsys, :submitter,
                    :block_number, :parent_hash, :state_root, :num_transactions, :gas_used,
                    :payload);
            ")?;

        let update_task_progress = conn.prepare(
            "
            INSERT INTO update_task_progress(
                    chain_id, blockhash, id_proofsys,
                    fulfiller, id_status, proof)
                VALUES (
                    :chain_id, :blockhash, :id_proofsys,
                    :fulfiller, :id_status, :proof);
            ")?;

        // The requires sqlite to be compiled with dbstat support:
        //      https://www.sqlite.org/dbstat.html
        // which is the case for rusqlite
        //      https://github.com/rusqlite/rusqlite/blob/v0.31.0/libsqlite3-sys/build.rs#L126
        // but may not be the case for system-wide sqlite when debugging.
        let get_db_size = conn.prepare(
            "
            SELECT
                name as table_name,
                SUM(pgsize) as table_size
            FROM dbstat
            GROUP BY table_name
            ORDER BY SUM(pgsize) DESC;
            "
        )?;

        let get_task_proof = conn.prepare(
            "
            SELECT proof
            FROM task_proofs tp
            LEFT JOIN
                tasks t ON tp.id_task = t.id_task
            WHERE 1=1
                AND t.chain_id = :chain_id
                AND t.blockhash = :blockhash
                AND t.id_proofsys = :id_proofsys
            LIMIT 1;
            ")?;

        let get_task_proving_status = conn.prepare(
            "
            SELECT
                t3p.thirdparty_desc,
                ts.id_status,
                MAX(timestamp)
            FROM
                task_status ts
            LEFT JOIN
                tasks t ON ts.id_task = t.id_task
            LEFT JOIN
                thirdparties t3p ON ts.id_thirdparty = t3p.id_thirdparty
            WHERE 1=1
                AND t.chain_id = :chain_id
                AND t.blockhash = :blockhash
                AND t.id_proofsys = :id_proofsys
            GROUP BY
                t3p.id_thirdparty
            ORDER BY
                ts.timestamp DESC;
            ")?;

        let get_tasks_unfinished = conn.prepare (
            "
            SELECT
                t.chain_id,
                t.blockhash,
                t.id_proofsys,
                t3p.thirdparty_desc,
                ts.id_status,
                MAX(timestamp)
            FROM
                task_status ts
            LEFT JOIN
                tasks t ON ts.id_task = t.id_task
            LEFT JOIN
                thirdparties t3p ON ts.id_thirdparty = t3p.id_thirdparty
            WHERE 1=1
                AND id_status NOT IN (
                        0, -- Success
                    -3000, -- Cancelled
                    -3100, -- Cancelled (never started)
                    -3200  -- Cancelled (aborted)
                    -- What do we do with -4000 Invalid/unsupported blocks?
                    -- And -9999 Unspecified failure reason?
                    -- For now we return them until we know more of the failure modes
                );
            ")?;

        Ok(TaskManager {
                enqueue_task,
                update_task_progress,
                get_task_proof,
                get_task_proving_status,
                get_tasks_unfinished,
                get_db_size })
    }
}

impl<'db> TaskManager<'db> {
    pub fn enqueue_task(
        &mut self,
        chain_id: ChainId,
        blockhash: &B256,
        proof_system: TaskProofsys,
        submitter: &str,
        block_number: BlockNumber,
        parent_hash: &B256,
        state_root: &B256,
        num_transactions: u64,
        gas_used: u64,
        payload: &[u8],
    ) -> Result<(), TaskManagerError> {
        self.enqueue_task.execute(named_params! {
            ":chain_id": chain_id as u64,
            ":blockhash": blockhash.as_slice(),
            ":id_proofsys": proof_system as u8,
            ":submitter": submitter,
            ":block_number": block_number,
            ":parent_hash": parent_hash.as_slice(),
            ":state_root": state_root.as_slice(),
            ":num_transactions": num_transactions,
            ":gas_used": gas_used,
            ":payload": payload,
        })?;
        Ok(())
    }

    pub fn update_task_progress(
        &mut self,
        chain_id: ChainId,
        blockhash: &B256,
        proof_system: TaskProofsys,
        fulfiller: Option<&str>,
        status: TaskStatus,
        proof: Option<&[u8]>,
    ) -> Result<(), TaskManagerError> {
        self.update_task_progress.execute(named_params! {
            ":chain_id": chain_id as u64,
            ":blockhash": blockhash.as_slice(),
            ":id_proofsys": proof_system as u8,
            ":fulfiller": fulfiller,
            ":id_status": status as i32,
            ":proof": proof
        })?;
        Ok(())
    }

    /// Returns the latest triplet (submitter or fulfiller, status, last update time)
    pub fn get_task_proving_status(
        &mut self,
        chain_id: ChainId,
        blockhash: &B256,
        proof_system: TaskProofsys,
    ) -> Result<Vec<(Option<String>, TaskStatus, DateTime<Utc>)>, TaskManagerError> {
        let rows = self.get_task_proving_status.query_map(named_params! {
            ":chain_id": chain_id as u64,
            ":blockhash": blockhash.as_slice(),
            ":id_proofsys": proof_system as u8,
        }, |row| Ok((
            row.get::<_, Option<String>>(0)?,
            TaskStatus::from(row.get::<_, i32>(1)?),
            row.get::<_, DateTime<Utc>>(2)?,
        )))?;
        let proving_status = rows.collect::<Result<Vec<_>, _>>()?;

        Ok(proving_status)
    }

    pub fn get_task_proof(
        &mut self,
        chain_id: ChainId,
        blockhash: &B256,
        proof_system: TaskProofsys,
    ) -> Result<Vec<u8>, TaskManagerError> {
        let proof = self.get_task_proof.query_row(named_params! {
            ":chain_id": chain_id as u64,
            ":blockhash": blockhash.as_slice(),
            ":id_proofsys": proof_system as u8,
        }, |r| r.get(0))?;

        Ok(proof)
    }

    /// Returns the total and detailed database size
    pub fn get_db_size(&mut self) -> Result<(usize, Vec<(String, usize)>), TaskManagerError> {
        let rows = self.get_db_size.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let details = rows.collect::<Result<Vec<_>, _>>()?;
        let total = details.iter().fold(0, |acc, item| acc + item.1);
        Ok((total, details))
    }

}

#[cfg(test)]
mod tests {
    // We only test private functions here.
    // Public API will be tested in a dedicated tests folder

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn error_on_missing() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("db.sqlite");
        assert!(TaskDb::open(&file).is_err());
    }

    #[test]
    fn ensure_exclusive() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("db.sqlite");

        let _db = TaskDb::create(&file).unwrap();
        assert!(TaskDb::open(&file).is_err());
    }

    #[test]
    fn ensure_unicity() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("db.sqlite");

        let _db = TaskDb::create(&file).unwrap();
        assert!(TaskDb::create(&file).is_err());
    }
}