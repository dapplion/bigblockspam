use anyhow::Result;
use dotenv::dotenv;
use ethers::{
    prelude::{k256::ecdsa::SigningKey, SignerMiddleware, U256},
    providers::{Middleware, Provider, StreamExt, Ws},
    signers::{LocalWallet, Signer},
    types::{Address, BlockId, BlockNumber, Eip1559TransactionRequest, TransactionRequest},
    utils::parse_units,
};
use futures::future::try_join_all;
use rand::Rng;
use sha3::{Digest, Sha3_256};
use std::{collections::BTreeMap, env};
use std::{
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const RPC_URL_WS_DEFAULT: &str = "wss://rpc.gnosischain.com/wss";

// From some tests, the network can easily accept tx with 129kB of data. Above that it strugles for
// inclusion. A single Blob is BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB = 32 * 4096 = 131072
//
// The gas cost of this data size:
// | N  | Gas      | % of block (30M)
// | -- | -------- | ----------------
// | 1  | 2097152  | 7
// | 2  | 4194304  | 21
// | 4  | 8388608  | 28
// | 6  | 12582912 | 41
// | 8  | 16777216 | 56
// | 12 | 25165824 | 83
const DATA_SIZE: usize = 131072;

/// How frequent to update the transaction rate
const TX_RATE_UPDATE_EVERY_BLOCKS: usize = 1;
const MAX_BLOCK_GAS: usize = 30_000_000;
const ONE_GWEI: f64 = 1_000_000_000.;
/// Transactions must be bumped by at least 10% to be re-accepted into the mempool
const MIN_GAS_FACTOR_BUMP: f64 = 1.2;
const MIN_GAS_PRIO_FEE: f64 = 10. * ONE_GWEI;
const MAX_NONCE_ENTRIES: usize = 10;

// Target for each account to submit one transaction per block
// On every block:
// - check gas price
// - check current nonce of account
// - broadcast new transaction with bumped gas price according to previous one

#[tokio::main]
async fn main() -> Result<()> {
    // Auto-load .env file
    dotenv().ok();

    // Read constants from environment variables
    let rpc_url_ws: String =
        env::var("RPC_URL_WS").unwrap_or_else(|_| RPC_URL_WS_DEFAULT.to_string());
    let privkey: String = env::var("PRIVKEY").unwrap();
    let skip_funding = env::var("SKIP_FUNDING").is_ok();

    let target_blobs_per_block = 3;
    let max_active_accounts = 15;
    let wallet_offset = 17;

    let target_balance: U256 = parse_units("2.0", "ether").unwrap().into();
    let min_balance: U256 = parse_units("1.5", "ether").unwrap().into();
    let target_address = Address::from_str("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();

    let provider = Provider::<Ws>::connect(&rpc_url_ws).await?;
    let chain_id = provider.get_chainid().await?.as_u128() as u64;

    // connect the wallet to the provider
    let parent_signing_key =
        SigningKey::from_bytes(hex::decode(privkey).unwrap().as_slice().into()).unwrap();
    let parent_wallet = SignerMiddleware::new(
        provider.clone(),
        LocalWallet::from(parent_signing_key.clone()).with_chain_id(chain_id),
    );

    println!(
        "connected to {} chain_id {} with parent account {}",
        rpc_url_ws,
        chain_id,
        parent_wallet.address()
    );

    // Compute sender accounts
    let wallets = (wallet_offset..wallet_offset + max_active_accounts)
        .map(|i| {
            let pk = derive_privkey_from_parent(&parent_signing_key, i);
            let wallet = LocalWallet::from(pk);
            SignerMiddleware::new(provider.clone(), wallet.with_chain_id(chain_id))
        })
        .collect::<Vec<_>>();

    let addresses = wallets
        .iter()
        .map(|wallet| wallet.address())
        .collect::<Vec<_>>();

    // Fund all sender accounts
    if skip_funding {
        println!("Skipping funding accounts");
    } else {
        for address in addresses.iter() {
            fund_account_up_to(&parent_wallet, *address, target_balance, min_balance).await?;
            println!(
                "funded account 0x{} with at least {} wei",
                hex::encode(address.to_fixed_bytes()),
                min_balance
            );
        }
    }

    send_transactions_to_self(&wallets).await?;
    println!("sent check transactions from all wallets");

    // Persist initial nonces, to estimate load
    let initial_block_number = provider.get_block_number().await?.as_usize();
    let initial_nonces = get_nonces(
        &provider,
        &addresses,
        BlockId::Number(BlockNumber::Number(initial_block_number.into())),
    )
    .await?;
    let mut prev_nonces = PrevNonces::default();
    prev_nonces.insert(initial_block_number, initial_nonces.clone());

    // Prevent sending transations again for the same height on re-orgs
    let mut transactions_sent_last_for_block = initial_block_number;
    let mut blobs_per_block: usize = target_blobs_per_block;
    let mut last_tx_rate_update_block = initial_block_number;
    let mut last_send_tx_by_wallet: Vec<Option<(usize, f64)>> = vec![None; max_active_accounts];

    let mut stream = provider.subscribe_blocks().await?;
    while let Some(block) = stream.next().await {
        let timestamp = block.timestamp.as_u128() as u64;
        let since_block = duration_since_timestamp_sec(timestamp);
        let block_number = block.number.unwrap().as_usize();
        let block_hash = block.hash.unwrap();
        let block_base_fee = block.base_fee_per_gas.unwrap().as_u64();

        // Prevent sending transations again for the same height on re-orgs
        if block_number > transactions_sent_last_for_block {
            transactions_sent_last_for_block = block_number;

            let nonces = get_nonces(&provider, &addresses, BlockId::Hash(block_hash)).await?;

            // Persist nonces
            prev_nonces.insert(block_number, nonces.clone());
            // Retrieve nonces from some pre-defined distance
            let nonces_at_some_distance = prev_nonces
                .get_oldest()
                .unwrap_or_else(|| initial_nonces.clone());

            let nonce_delta: usize = nonces
                .iter()
                .zip(nonces_at_some_distance)
                .map(|(nonce, init_nonce)| nonce - init_nonce)
                .sum();
            let tx_rate = nonce_delta as f64 / (block_number - initial_block_number) as f64;

            // Compute how many accounts should _attempt_ to include transactions in this block
            if block_number > last_tx_rate_update_block + TX_RATE_UPDATE_EVERY_BLOCKS {
                last_tx_rate_update_block = block_number;
                if tx_rate > target_blobs_per_block as f64 {
                    blobs_per_block = blobs_per_block.saturating_sub(1);
                } else {
                    blobs_per_block = std::cmp::min(blobs_per_block + 1, max_active_accounts);
                }
                println!(
                    "Measured tx rate: {}, updating rate to {}",
                    tx_rate, blobs_per_block
                );
            }

            println!(
                "Block event {} {}, arrived: {:?} late {:?}, gas used: {} {}% | measured tx rate: {} broadcast rate: {}",
                block_number,
                block_hash,
                timestamp,
                since_block,
                block.gas_used,
                (100 * block.gas_used.as_usize()) / MAX_BLOCK_GAS,
                tx_rate,
                blobs_per_block,
            );

            for i in 0..blobs_per_block {
                let wallet = wallets.get(i).unwrap().clone();
                let nonce = *nonces.get(i).unwrap();

                let last_sent_factor = match last_send_tx_by_wallet.get(i).unwrap() {
                    Some((last_sent_nonce, factor)) => {
                        if *last_sent_nonce == nonce {
                            println!("resending transaction from account {} factor {}", i, factor);
                            Some(factor)
                        } else {
                            None
                        }
                    }
                    None => None,
                };
                let factor = match last_sent_factor {
                    Some(factor) => factor * MIN_GAS_FACTOR_BUMP,
                    None => 1.,
                };
                *last_send_tx_by_wallet.get_mut(i).unwrap() = Some((nonce, factor));

                // 131072 bytes * 16 gas / byte + 21_000 = 2118152 gas
                // * 20Gwei per gas = 42363040000000000 wei = 0.042 ETH
                let max_base_fee = (factor * 1.25 * block_base_fee as f64) as u64;
                let max_prio_fee = (factor * MIN_GAS_PRIO_FEE) as u64;
                tokio::spawn(async move {
                    let tx = Eip1559TransactionRequest::new()
                        .to(target_address)
                        .value(0)
                        .from(wallet.address())
                        .data(get_random_data())
                        .nonce(nonce)
                        .max_priority_fee_per_gas(max_prio_fee)
                        .max_fee_per_gas(max_base_fee + max_prio_fee);

                    let mut tx = tx.into();
                    // fill any missing fields
                    wallet
                        .fill_transaction(&mut tx, Some(BlockId::Hash(block_hash)))
                        .await
                        .unwrap();

                    // if we have a nonce manager set, we should try handling the result in
                    // case there was a nonce mismatch
                    let signature = wallet
                        .sign_transaction(&tx, wallet.address())
                        .await
                        .unwrap();
                    let signed_tx = tx.rlp_signed(&signature);

                    // Submit the raw transaction
                    let tx = match wallet.send_raw_transaction(signed_tx).await {
                        Ok(tx) => tx,
                        Err(e) => {
                            return eprintln!(
                                "Error sending tx: {:?}\n{:?}",
                                e,
                                tx.set_data([].into())
                            )
                        }
                    };

                    let tx = tx.await.unwrap();
                    println!(
                        "confirmed tx in block {:?} sent after block {}",
                        tx.map(|tx| tx.block_number),
                        block_number
                    );
                });
            }
        } else {
            println!("Block event {} {}, re-orged", block_number, block_hash,);
        }
    }

    Ok(())
}

#[derive(Default)]
struct PrevNonces {
    nonces: BTreeMap<usize, Vec<usize>>,
}

impl PrevNonces {
    pub fn insert(&mut self, k: usize, v: Vec<usize>) {
        self.nonces.insert(k, v);
        self.prune();
    }

    pub fn get_oldest(&mut self) -> Option<Vec<usize>> {
        self.nonces.first_entry().map(|e| e.get().clone())
    }

    fn prune(&mut self) {
        let highest_key = if let Some((highest_key, _)) = self.nonces.last_key_value() {
            *highest_key
        } else {
            return;
        };

        while let Some(entry) = self.nonces.first_entry() {
            if *entry.key() < highest_key - MAX_NONCE_ENTRIES {
                entry.remove();
            } else {
                break;
            }
        }
    }
}

fn get_random_data() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut random_bytes: Vec<u8> = Vec::with_capacity(DATA_SIZE);
    for _ in 0..DATA_SIZE {
        random_bytes.push(rng.gen());
    }
    random_bytes
}

fn duration_since_timestamp_sec(timestamp: u64) -> Duration {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let target_time = Duration::from_secs(timestamp);

    if current_time > target_time {
        current_time - target_time
    } else {
        Duration::from_secs(0)
    }
}

fn derive_privkey_from_parent(parent_privkey: &SigningKey, i: usize) -> SigningKey {
    let mut hasher = Sha3_256::new();
    hasher.update(parent_privkey.to_bytes());
    hasher.update(i.to_be_bytes());
    let result = hasher.finalize();
    SigningKey::from_bytes(&result).unwrap()
}

async fn fund_account_up_to(
    parent_wallet: &SignerMiddleware<Provider<Ws>, LocalWallet>,
    child_address: Address,
    target_balance: U256,
    min_balance: U256,
) -> Result<()> {
    let current_balance = parent_wallet.get_balance(child_address, None).await?;

    parent_wallet.get_balance(child_address, None).await?;

    if current_balance < min_balance {
        let amount_to_send = target_balance - current_balance;
        let tx = TransactionRequest::new()
            .to(child_address)
            .from(parent_wallet.address())
            .value(amount_to_send);
        let _ = parent_wallet.send_transaction(tx, None).await?.await?;
    }

    Ok(())
}

async fn get_nonces(
    provider: &Provider<Ws>,
    addresses: &[Address],
    block: BlockId,
) -> Result<Vec<usize>> {
    try_join_all(
        addresses
            .iter()
            .map(|address| async move {
                let nonce = provider
                    .get_transaction_count(*address, Some(block))
                    .await?;
                Ok(nonce.as_usize())
            })
            .collect::<Vec<_>>(),
    )
    .await
}

async fn send_transactions_to_self(
    wallets: &[SignerMiddleware<Provider<Ws>, LocalWallet>],
) -> Result<()> {
    try_join_all(
        wallets
            .iter()
            .map(|wallet| async move {
                let tx = Eip1559TransactionRequest::new()
                    .to(wallet.address())
                    .value(0)
                    .from(wallet.address())
                    .data(get_random_data());

                let _ = wallet
                    .send_transaction(tx, None)
                    .await
                    .unwrap()
                    .await
                    .unwrap();

                Ok::<_, anyhow::Error>(())
            })
            .collect::<Vec<_>>(),
    )
    .await?;
    Ok(())
}
