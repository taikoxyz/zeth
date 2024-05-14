// Raiko
// Copyright (c) 2024 Taiko Labs
// Licensed and distributed under either of
//   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
//   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
// at your option. This file may not be copied, modified, or distributed except according to those terms.

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use raiko_primitives::B256;
    use task_manager::{TaskDb, TaskProofsys};

    #[test]
    fn test_enqueue_task() {

        // // Materialized local DB
        // let dir = std::env::current_dir().unwrap().join("tests");
        // let file = dir.as_path().join("test_enqueue_task.sqlite");
        // if file.exists() {
        //     std::fs::remove_file(&file).unwrap()
        // };

        // temp dir DB
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let file = dir.path().join("test_enqueue_task.sqlite");

        #[allow(unused_mut)]
        let mut db = TaskDb::open_or_create(&file).unwrap();
        // db.set_tracer(Some(|stmt| println!("sqlite:\n-------\n{}\n=======", stmt)));
        let mut tama = db.manage().unwrap();

        let mut rng = ChaCha8Rng::seed_from_u64(123);

        let chain_id = 100;
        let blockhash = B256::random();
        let proofsys = TaskProofsys::Risc0;
        let submitter = "test_enqueue_task";
        let block_number = rng.gen_range(1..4_000_000);
        let parent_hash = B256::random();
        let state_root = B256::random();
        let num_transactions = rng.gen_range(0..1000);
        let gas_used = rng.gen_range(0..100_000_000);
        let payload_length = rng.gen_range(20..200);
        let payload: Vec<u8> = (&mut rng).gen_iter::<u8>().take(payload_length).collect();

        tama.enqueue_task(
            chain_id,
            &blockhash,
            proofsys,
            submitter,
            block_number,
            &parent_hash,
            &state_root,
            num_transactions,
            gas_used,
            &payload,
        ).unwrap();
    }

    #[test]
    fn test_get_db_size() {

        // Materialized local DB
        let dir = std::env::current_dir().unwrap().join("tests");
        let file = dir.as_path().join("test_get_db_size.sqlite");
        if file.exists() {
            std::fs::remove_file(&file).unwrap()
        };

        // // temp dir DB
        // use tempfile::tempdir;
        // let dir = tempdir().unwrap();
        // let file = dir.path().join("test_get_db_size.sqlite");

        #[allow(unused_mut)]
        let mut db = TaskDb::open_or_create(&file).unwrap();
        // db.set_tracer(Some(|stmt| println!("sqlite:\n-------\n{}\n=======", stmt)));
        let mut tama = db.manage().unwrap();

        let mut rng = ChaCha8Rng::seed_from_u64(123);

        for _ in 0..42 {
            let chain_id = 100;
            let blockhash = B256::random();
            let proofsys = TaskProofsys::Risc0;
            let submitter = "test_get_db_size";
            let block_number = rng.gen_range(1..4_000_000);
            let parent_hash = B256::random();
            let state_root = B256::random();
            let num_transactions = rng.gen_range(0..1000);
            let gas_used = rng.gen_range(0..100_000_000);
            let payload_length = rng.gen_range(1_000_000..10_000_000);
            let payload: Vec<u8> = (&mut rng).gen_iter::<u8>().take(payload_length).collect();

            tama.enqueue_task(
                chain_id,
                &blockhash,
                proofsys,
                submitter,
                block_number,
                &parent_hash,
                &state_root,
                num_transactions,
                gas_used,
                &payload,
            ).unwrap();
        }

        let (db_size, db_tables_size) = tama.get_db_size().unwrap();
        println!("db_tables_size: {:?}", db_tables_size);
        assert!(db_size / 1024 / 1024 > 40);
    }
}