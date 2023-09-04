use anyhow::{Context, Result};
use ethers::{
    prelude::{k256::ecdsa::SigningKey, SignerMiddleware, U256},
    providers::{Middleware, Provider, StreamExt, Ws},
    signers::{LocalWallet, Signer},
    types::{Address, BlockId, BlockNumber, Eip1559TransactionRequest, TransactionRequest},
    utils::parse_units,
};
use futures::stream::{self, TryStreamExt};
use rand::Rng;
use sha3::{Digest, Sha3_256};
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const RPC_URL_WS: &str = "wss://rpc.gnosischain.com/wss";

const PRIVKEY: &str = "040fff5339f9cb617826a40de1d8c6af978eb9aff246c20153c105b655defb42";
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

// Target for each account to submit one transaction per block
// On every block:
// - check gas price
// - check current nonce of account
// - broadcast new transaction with bumped gas price according to previous one

#[tokio::main]
async fn main() -> Result<()> {
    let target_blobs_per_block = 4;
    let max_active_accounts = 12;
    let target_balance: U256 = parse_units("1.0", "ether").unwrap().into();
    let min_balance: U256 = parse_units("0.8", "ether").unwrap().into();
    let target_address = Address::from_str("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();

    let provider = Provider::<Ws>::connect(RPC_URL_WS).await?;
    let chain_id = provider.get_chainid().await?.as_u128() as u64;

    // connect the wallet to the provider
    let parent_signing_key =
        SigningKey::from_bytes(hex::decode(PRIVKEY).unwrap().as_slice().into()).unwrap();
    let parent_wallet = SignerMiddleware::new(
        provider.clone(),
        LocalWallet::from(parent_signing_key.clone()).with_chain_id(chain_id),
    );

    println!(
        "connected to {} chain_id {} with parent account {}",
        RPC_URL_WS,
        chain_id,
        parent_wallet.address()
    );

    // Compute sender accounts
    let wallets = (0..max_active_accounts)
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
    for address in addresses.iter() {
        fund_account_up_to(&parent_wallet, *address, target_balance, min_balance).await?;
        println!(
            "funded account 0x{} with {} wei",
            hex::encode(&address.to_fixed_bytes()),
            min_balance
        );
    }

    // Persist initial nonces, to estimate load
    let initial_block_number = provider.get_block_number().await?.as_usize();
    let mut addresses_with_init_nonce = vec![];
    for address in addresses.iter() {
        let nonce = provider
            .get_transaction_count(
                *address,
                Some(BlockId::Number(BlockNumber::Number(
                    initial_block_number.into(),
                ))),
            )
            .await?
            .as_usize();
        addresses_with_init_nonce.push((nonce, *address));
    }

    // Prevent sending transations again for the same height on re-orgs
    let mut transactions_sent_last_for_block = initial_block_number;
    let mut blobs_per_block: usize = target_blobs_per_block;
    let mut last_tx_rate_update_block = initial_block_number;
    let nonce_delta_last_block = Arc::new(AtomicUsize::new(0));

    let mut stream = provider.subscribe_blocks().await?;
    while let Some(block) = stream.next().await {
        let timestamp = block.timestamp.as_u128() as u64;
        let since_block = duration_since_timestamp_sec(timestamp);
        let block_number = block.number.unwrap().as_usize();
        let block_hash = block.hash.unwrap();
        println!(
            "Ts: {:?} {:?}, block number: {} -> {:?}, gas used: {} {}%",
            timestamp,
            since_block,
            block_number,
            block_hash,
            block.gas_used,
            (100 * block.gas_used.as_usize()) / MAX_BLOCK_GAS
        );

        // Prevent sending transations again for the same height on re-orgs
        if block_number > transactions_sent_last_for_block {
            transactions_sent_last_for_block = block_number;

            // Compute how many accounts should _attempt_ to include transactions in this block
            if block_number > last_tx_rate_update_block + TX_RATE_UPDATE_EVERY_BLOCKS {
                last_tx_rate_update_block = block_number;
                let recent_tx_rate = nonce_delta_last_block.load(Ordering::Relaxed) as f64
                    / (block_number - initial_block_number) as f64;
                if recent_tx_rate > target_blobs_per_block as f64 {
                    blobs_per_block = blobs_per_block.saturating_sub(1);
                } else {
                    blobs_per_block = std::cmp::min(blobs_per_block + 1, max_active_accounts);
                }
                println!(
                    "Measured tx rate: {}, updating rate to {}",
                    recent_tx_rate, blobs_per_block
                );
            }

            for i in 0..blobs_per_block {
                let wallet = wallets.get(i).unwrap().clone();
                // 131072 bytes * 16 gas / byte + 21_000 = 2118152 gas
                // * 20Gwei per gas = 42363040000000000 wei = 0.042 ETH
                tokio::spawn(async move {
                    let tx = Eip1559TransactionRequest::new()
                        .to(target_address)
                        .value(0)
                        .from(wallet.address())
                        .data(get_random_data())
                        .max_priority_fee_per_gas(20_000_000_000_u64)
                        .max_fee_per_gas(2_000_000_000);

                    let tx = wallet
                        .send_transaction(tx, None)
                        .await
                        .unwrap()
                        .await
                        .unwrap();
                    println!("confirmed tx in block {:?}", tx.map(|tx| tx.block_number));
                });
            }

            // Lazily update nonce_delta since getting the exact value is not necessary
            let parent_wallet = parent_wallet.clone();
            let addresses_with_init_nonce = addresses_with_init_nonce.clone();
            let nonce_delta_last_block = nonce_delta_last_block.clone();
            tokio::spawn(async move {
                let block_number_delta = block_number - initial_block_number;
                let nonce_delta = get_nonce_delta(
                    &parent_wallet,
                    &addresses_with_init_nonce,
                    BlockId::Hash(block_hash),
                )
                .await
                .unwrap();
                nonce_delta_last_block.store(nonce_delta, Ordering::Relaxed);
                let tx_rate = nonce_delta as f64 / block_number_delta as f64;
                println!(
                    "nonce_delta {} in blocks {} rate {} - block {} {}",
                    nonce_delta, block_number_delta, tx_rate, block_hash, block_number
                )
            });
        }
    }

    Ok(())
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

async fn get_nonce_delta(
    parent_wallet: &SignerMiddleware<Provider<Ws>, LocalWallet>,
    addresses_with_init_nonce: &[(usize, Address)],
    block: BlockId,
) -> Result<usize> {
    let nonce_delta = Arc::new(AtomicUsize::new(0));

    stream::iter(addresses_with_init_nonce.iter().map(Ok))
        .try_for_each_concurrent(10, |(init_nonce, address)| {
            let nonce_delta = nonce_delta.clone();
            async move {
                let nonce = parent_wallet
                    .get_transaction_count(*address, Some(block))
                    .await
                    .context("Failed to get transaction count")?;
                nonce_delta.fetch_add(nonce.as_usize() - init_nonce, Ordering::Relaxed);
                Ok::<_, anyhow::Error>(())
            }
        })
        .await?;

    Ok(nonce_delta.load(Ordering::Relaxed))
}
