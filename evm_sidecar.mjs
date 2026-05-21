#!/usr/bin/env node
import { ethers } from 'ethers';

const BASE_RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
const BSC_RPC_URL = process.env.BSC_RPC_URL || 'https://bsc-dataseed.binance.org';
const ONEINCH_API_KEY = process.env.ONEINCH_API_KEY || '';
const DEBRIDGE_API_URL = process.env.DEBRIDGE_API_URL || 'https://dln.debridge.finance/v1.0';
const DEBRIDGE_STATS_API = 'https://stats-api.dln.trade';

const command = process.argv[2];
// Read payload from stdin
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const stdinData = Buffer.concat(chunks).toString();
const payload = stdinData.trim() ? JSON.parse(stdinData) : {};

async function main() {
    try {
        let result;
        switch (command) {
            case 'generate': {
                // Generate a random EVM wallet
                const wallet = ethers.Wallet.createRandom();
                result = {
                    success: true,
                    data: {
                        address: wallet.address,
                        privateKey: wallet.privateKey,
                    }
                };
                break;
            }
            case 'balance': {
                // Get ETH/BNB balance + ERC-20 token balances on EVM chain
                const balChainId = payload.chain_id || 8453;
                const balRpcUrl = balChainId === 56 ? BSC_RPC_URL : BASE_RPC_URL;
                const provider = new ethers.JsonRpcProvider(balRpcUrl);
                const address = payload.address;
                if (!address) {
                    result = { success: false, error: 'address required' };
                    break;
                }
                const ethBalance = await provider.getBalance(address);
                const balanceData = {
                    eth_balance: ethers.formatEther(ethBalance),
                    eth_balance_wei: ethBalance.toString(),
                    tokens: [],
                };

                // Auto-discover tokens: use provided list or scan common Base tokens
                let tokenList = (payload.tokens && Array.isArray(payload.tokens) && payload.tokens.length > 0) ? payload.tokens : [];
                if (tokenList.length === 0) {
                    // Common Base tokens to scan for balances
                    tokenList = [
                        '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', // USDC
                        '0x4200000000000000000000000000000000000006', // WETH
                        '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb', // DAI
                        '0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b', // VIRTUAL
                        '0xfA980cEd6895AC314E7dE34Ef1bFAE90a5AdD21b', // PRIME
                        '0x532f27101965dd16442E59d40670FaF5eBB142E4', // BRETT
                        '0x940181a94A35A4569E4529A3CDfB74e38FD98631', // AERO
                        '0xB1a03EdA10342529bBF8EB700a06C60441fEf25d', // MIGGLES
                        '0x768BE13e1680b5Ebe0024C42c896E3dB59ec0149', // MOCHI
                        '0xAC1Bd2486aAf3B5C0fc3Fd868558b082a531B2B4', // TOSHI
                        '0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed', // DEGEN
                        '0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf', // cbBTC
                        '0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22', // cbETH
                        '0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA', // USDbC
                    ];
                }
                if (tokenList.length > 0) {
                    const erc20Abi = ['function balanceOf(address) view returns (uint256)', 'function symbol() view returns (string)', 'function decimals() view returns (uint8)'];
                    // Query all tokens in parallel for speed
                    const tokenPromises = tokenList.map(async (tokenAddr) => {
                        try {
                            const contract = new ethers.Contract(tokenAddr, erc20Abi, provider);
                            const [balance, symbol, decimals] = await Promise.all([
                                contract.balanceOf(address),
                                contract.symbol().catch(() => 'UNKNOWN'),
                                contract.decimals().catch(() => 18),
                            ]);
                            if (balance > 0n) {
                                return {
                                    address: tokenAddr,
                                    symbol,
                                    decimals: Number(decimals),
                                    balance: ethers.formatUnits(balance, decimals),
                                    balance_raw: balance.toString(),
                                };
                            }
                            return null;
                        } catch (e) {
                            return null; // Skip errored tokens silently
                        }
                    });
                    const results = await Promise.allSettled(tokenPromises);
                    for (const r of results) {
                        if (r.status === 'fulfilled' && r.value) {
                            balanceData.tokens.push(r.value);
                        }
                    }
                }
                // Fetch logos from DexScreener for tokens with balance
                if (balanceData.tokens.length > 0) {
                    const dexChain = balChainId === 56 ? 'bsc' : 'base';
                    const logoPromises = balanceData.tokens.map(async (t) => {
                        try {
                            const resp = await fetch(`https://api.dexscreener.com/tokens/v1/${dexChain}/${t.address}`, { signal: AbortSignal.timeout(5000) });
                            if (resp.ok) {
                                const pairs = await resp.json();
                                if (Array.isArray(pairs) && pairs.length > 0 && pairs[0].info?.imageUrl) {
                                    t.logo_uri = pairs[0].info.imageUrl;
                                }
                            }
                        } catch { /* non-fatal */ }
                    });
                    await Promise.allSettled(logoPromises);
                }
                result = { success: true, data: balanceData };
                break;
            }
            case 'debridge-quote': {
                // Get quote + create-tx from deBridge DLN API (Solana → Base)
                const {
                    src_chain_id,       // 7565164 (Solana)
                    dst_chain_id,       // 8453 (Base)
                    src_token_in,       // SOL mint address
                    dst_token_out,      // 0x... Base token
                    src_amount,         // amount in lamports
                    dst_recipient,      // pocket EVM address
                    src_authority,      // pocket Solana pubkey
                    dst_authority,      // pocket EVM address
                    affiliate_fee_percent,
                    affiliate_fee_recipient,
                    referral_code,
                } = payload;

                const params = new URLSearchParams({
                    srcChainId: String(src_chain_id || 7565164),
                    dstChainId: String(dst_chain_id || 8453),
                    srcChainTokenIn: src_token_in || 'So11111111111111111111111111111111111111112',
                    dstChainTokenOut: dst_token_out,
                    srcChainTokenInAmount: String(src_amount),
                    dstChainTokenOutAmount: 'auto',
                    dstChainTokenOutRecipient: dst_recipient,
                    srcChainOrderAuthorityAddress: src_authority,
                    dstChainOrderAuthorityAddress: dst_authority || dst_recipient,
                    prependOperatingExpenses: 'true',
                });

                if (affiliate_fee_percent) {
                    params.set('affiliateFeePercent', String(affiliate_fee_percent));
                }
                if (affiliate_fee_recipient) {
                    params.set('affiliateFeeRecipient', affiliate_fee_recipient);
                }
                if (referral_code) {
                    params.set('referralCode', String(referral_code));
                }

                const url = `${DEBRIDGE_API_URL}/dln/order/create-tx?${params.toString()}`;
                const resp = await fetch(url);
                const data = await resp.json();

                if (data.errorId || data.error) {
                    result = { success: false, error: data.errorId || data.error, details: data };
                } else {
                    result = {
                        success: true,
                        data: {
                            estimation: data.estimation,
                            tx: data.tx,
                            order_id: data.orderId,
                            order: data.order,
                        }
                    };
                }
                break;
            }
            case 'debridge-quote-reverse': {
                // Get quote + create-tx from deBridge DLN API (EVM -> Solana)
                const {
                    src_chain_id,       // EVM chain ID (8453=Base, 56=BSC)
                    src_token_in,       // 0x... EVM token to sell
                    src_amount,         // amount in token's smallest unit
                    dst_recipient,      // pocket Solana pubkey
                    src_authority,      // pocket EVM address
                    dst_authority,      // pocket Solana pubkey
                    affiliate_fee_percent,
                    affiliate_fee_recipient,
                    referral_code,
                } = payload;

                const params = new URLSearchParams({
                    srcChainId: String(src_chain_id || 8453),
                    dstChainId: '7565164',
                    srcChainTokenIn: src_token_in,
                    dstChainTokenOut: 'So11111111111111111111111111111111111111112',
                    srcChainTokenInAmount: String(src_amount),
                    dstChainTokenOutAmount: 'auto',
                    dstChainTokenOutRecipient: dst_recipient,
                    srcChainOrderAuthorityAddress: src_authority,
                    dstChainOrderAuthorityAddress: dst_authority || dst_recipient,
                    prependOperatingExpenses: 'true',
                });

                if (affiliate_fee_percent) {
                    params.set('affiliateFeePercent', String(affiliate_fee_percent));
                }
                if (affiliate_fee_recipient) {
                    params.set('affiliateFeeRecipient', affiliate_fee_recipient);
                }
                if (referral_code) {
                    params.set('referralCode', String(referral_code));
                }

                const url = `${DEBRIDGE_API_URL}/dln/order/create-tx?${params.toString()}`;
                const resp = await fetch(url);
                const data = await resp.json();

                if (data.errorId || data.error) {
                    result = { success: false, error: data.errorId || data.error, details: data };
                } else {
                    result = {
                        success: true,
                        data: {
                            estimation: data.estimation,
                            tx: data.tx,
                            order_id: data.orderId,
                            order: data.order,
                        }
                    };
                }
                break;
            }
            case 'evm-approve-and-send': {
                // Approve ERC-20 token + send deBridge tx on EVM chain
                // Required for reverse flow: sell EVM token -> SOL
                const { private_key, approve_to, approve_token, approve_amount, tx_to, tx_data, tx_value, chain_id } = payload;

                const aasChainId = chain_id || 8453;
                const aasRpcUrl = aasChainId === 56 ? BSC_RPC_URL : BASE_RPC_URL;
                const provider = new ethers.JsonRpcProvider(aasRpcUrl);
                const wallet = new ethers.Wallet(private_key, provider);

                // Step 1: Approve ERC-20 if needed
                if (approve_to && approve_token && approve_amount) {
                    try {
                        const erc20 = new ethers.Contract(approve_token, [
                            'function approve(address spender, uint256 amount) returns (bool)',
                            'function allowance(address owner, address spender) view returns (uint256)',
                        ], wallet);

                        // Check current allowance
                        const currentAllowance = await erc20.allowance(wallet.address, approve_to);
                        const needed = BigInt(approve_amount);

                        if (currentAllowance < needed) {
                            const approveTx = await erc20.approve(approve_to, needed);
                            const approveReceipt = await approveTx.wait();
                            if (!approveReceipt || approveReceipt.status !== 1) {
                                result = { success: false, error: 'ERC-20 approve transaction failed' };
                                break;
                            }
                        }
                    } catch (e) {
                        result = { success: false, error: `ERC-20 approve failed: ${e.message}` };
                        break;
                    }
                }

                // Step 2: Send the deBridge transaction
                try {
                    const txReq = {
                        to: tx_to,
                        data: tx_data,
                        value: tx_value || '0',
                    };

                    // Estimate gas
                    try {
                        const gasEstimate = await provider.estimateGas({ ...txReq, from: wallet.address });
                        txReq.gasLimit = gasEstimate * 130n / 100n; // 30% buffer
                    } catch (e) {
                        // Use fallback gas limit
                        txReq.gasLimit = 500000n;
                    }

                    const txResponse = await wallet.sendTransaction(txReq);
                    const receipt = await txResponse.wait();

                    result = {
                        success: true,
                        data: {
                            tx_hash: receipt.hash,
                            block_number: receipt.blockNumber,
                            gas_used: receipt.gasUsed.toString(),
                            status: receipt.status,
                        }
                    };
                } catch (e) {
                    result = { success: false, error: `EVM transaction failed: ${e.message}` };
                }
                break;
            }
            case 'order-status': {
                // Check deBridge order status by orderId or txHash
                const { order_id, tx_hash } = payload;
                let orderId = order_id;

                // If we have tx_hash but no order_id, resolve it first
                if (!orderId && tx_hash) {
                    const txResp = await fetch(`${DEBRIDGE_STATS_API}/api/Transaction/${tx_hash}/orderIds`);
                    const txData = await txResp.json();
                    if (Array.isArray(txData) && txData.length > 0) {
                        orderId = txData[0];
                    } else {
                        result = { success: false, error: 'Could not resolve orderId from txHash', details: txData };
                        break;
                    }
                }

                if (!orderId) {
                    result = { success: false, error: 'order_id or tx_hash required' };
                    break;
                }

                const statusResp = await fetch(`${DEBRIDGE_STATS_API}/api/Orders/${orderId}`);
                const statusData = await statusResp.json();
                result = { success: true, data: statusData };
                break;
            }
            case 'evm-swap': {
                // Swap tokens via 1inch Aggregation Router (Base + BSC)
                const {
                    private_key,
                    src_token,
                    dest_token,
                    amount,
                    src_decimals,
                    dest_decimals,
                    slippage,
                    chain_id,
                } = payload;

                if (!private_key || !src_token || !dest_token || !amount) {
                    result = { success: false, error: 'private_key, src_token, dest_token, amount required' };
                    break;
                }

                // Dynamic RPC based on chain
                const swapChainId = chain_id || 8453;
                const swapRpcUrl = swapChainId === 56 ? BSC_RPC_URL : BASE_RPC_URL;
                const swapProvider = new ethers.JsonRpcProvider(swapRpcUrl);
                const swapWallet = new ethers.Wallet(private_key, swapProvider);
                const swapUserAddress = swapWallet.address;

                // Convert slippage from basis points to percent (100 bps = 1%)
                const slippagePct = (slippage || 100) / 100;

                // 1. Get swap TX from 1inch API
                const swapParams = new URLSearchParams({
                    src: src_token,
                    dst: dest_token,
                    amount: String(amount),
                    from: swapUserAddress,
                    slippage: String(slippagePct),
                    disableEstimate: 'true',
                    includeGas: 'true',
                });

                const swapUrl = `https://api.1inch.dev/swap/v6.0/${swapChainId}/swap?${swapParams.toString()}`;
                const swapHeaders = { 'Authorization': `Bearer ${ONEINCH_API_KEY}` };
                const swapResp = await fetch(swapUrl, { headers: swapHeaders });
                const swapData = await swapResp.json();

                if (swapData.error || swapData.statusCode) {
                    result = { success: false, error: `1inch swap failed: ${swapData.error || swapData.description || 'Unknown error'}` };
                    break;
                }

                if (!swapData.tx) {
                    result = { success: false, error: '1inch did not return tx data' };
                    break;
                }

                const destAmount = swapData.dstAmount || '0';
                const routerAddr = swapData.tx.to;

                // 2. Approve ERC-20 if src_token is not native ETH/BNB
                const nativeEth = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE';
                if (src_token.toLowerCase() !== nativeEth.toLowerCase()) {
                    try {
                        const erc20 = new ethers.Contract(src_token, [
                            'function approve(address spender, uint256 amount) returns (bool)',
                            'function allowance(address owner, address spender) view returns (uint256)',
                        ], swapWallet);

                        const currentAllowance = await erc20.allowance(swapUserAddress, routerAddr);
                        const needed = BigInt(amount);

                        if (currentAllowance < needed) {
                            const approveTx = await erc20.approve(routerAddr, needed);
                            const approveReceipt = await approveTx.wait();
                            if (!approveReceipt || approveReceipt.status !== 1) {
                                result = { success: false, error: 'ERC-20 approve failed for 1inch' };
                                break;
                            }
                        }
                    } catch (e) {
                        result = { success: false, error: `ERC-20 approve failed: ${e.message}` };
                        break;
                    }
                }

                // 3. Send swap TX
                try {
                    const txReq = {
                        to: swapData.tx.to,
                        data: swapData.tx.data,
                        value: swapData.tx.value || '0',
                        gasPrice: swapData.tx.gasPrice,
                    };

                    try {
                        const gasEstimate = await swapProvider.estimateGas({ ...txReq, from: swapUserAddress });
                        txReq.gasLimit = gasEstimate * 130n / 100n;
                    } catch (e) {
                        txReq.gasLimit = 500000n;
                    }

                    const txResponse = await swapWallet.sendTransaction(txReq);
                    const receipt = await txResponse.wait();

                    result = {
                        success: receipt.status === 1,
                        data: {
                            tx_hash: receipt.hash,
                            dest_amount: destAmount,
                            block_number: receipt.blockNumber,
                            gas_used: receipt.gasUsed.toString(),
                        }
                    };
                } catch (e) {
                    result = { success: false, error: `Swap TX failed: ${e.message}` };
                }
                break;
            }
            case 'debridge-execute': {
                // Full flow following official deBridge example:
                // 1. Fetch quote+TX from deBridge API
                // 2. Deserialize, simulate, update CU, replace blockhash, sign, submit
                const { Connection, VersionedTransaction, Keypair } = await import('@solana/web3.js');
                const bs58 = (await import('bs58')).default;

                const {
                    src_chain_id,
                    dst_chain_id,
                    src_token_in,
                    dst_token_out,
                    src_amount,
                    dst_recipient,
                    src_authority,
                    dst_authority,
                    affiliate_fee_percent,
                    affiliate_fee_recipient,
                    referral_code,
                    pocket_private_key,
                    solana_rpc_url,
                } = payload;

                if (!pocket_private_key || !solana_rpc_url) {
                    result = { success: false, error: 'pocket_private_key and solana_rpc_url required' };
                    break;
                }

                const conn = new Connection(solana_rpc_url, { commitment: 'confirmed' });
                const secretKey = bs58.decode(pocket_private_key);
                const signer = Keypair.fromSecretKey(secretKey);

                // 1. Fetch quote + TX from deBridge
                const execParams = new URLSearchParams({
                    srcChainId: String(src_chain_id || 7565164),
                    dstChainId: String(dst_chain_id || 8453),
                    srcChainTokenIn: src_token_in || 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
                    dstChainTokenOut: dst_token_out,
                    srcChainTokenInAmount: String(src_amount),
                    dstChainTokenOutAmount: 'auto',
                    dstChainTokenOutRecipient: dst_recipient,
                    srcChainOrderAuthorityAddress: src_authority,
                    dstChainOrderAuthorityAddress: dst_authority || dst_recipient,
                    prependOperatingExpenses: 'false',
                });

                if (affiliate_fee_percent) {
                    execParams.set('affiliateFeePercent', String(affiliate_fee_percent));
                }
                if (affiliate_fee_recipient) {
                    execParams.set('affiliateFeeRecipient', affiliate_fee_recipient);
                }
                if (referral_code) {
                    execParams.set('referralCode', String(referral_code));
                }

                const execUrl = `${DEBRIDGE_API_URL}/dln/order/create-tx?${execParams.toString()}`;
                const execResp = await fetch(execUrl);
                const execData = await execResp.json();

                if (execData.errorId || execData.error) {
                    result = { success: false, error: execData.errorId || execData.error, details: execData };
                    break;
                }

                if (!execData.tx || !execData.tx.data) {
                    result = { success: false, error: 'deBridge did not return transaction data', details: { keys: Object.keys(execData) } };
                    break;
                }

                // 2. Deserialize TX
                const txHex = execData.tx.data.replace('0x', '');
                const txBuf = Buffer.from(txHex, 'hex');
                let tx = VersionedTransaction.deserialize(txBuf);

                // 3. prepareSolanaTransaction (following official deBridge example)
                // Step A: Replace blockhash + sign for simulation
                let latestBh = await conn.getLatestBlockhash('confirmed');
                tx.message.recentBlockhash = latestBh.blockhash;
                tx.sign([signer]);

                // Step B: Simulate to get unitsConsumed
                const simulatedTx = await conn.simulateTransaction(tx);
                const used = simulatedTx.value.unitsConsumed || 200000;
                const NEW_CU_LIMIT = Math.ceil(used * 1.1);

                // Step C: Get priority fee
                const feeHistory = await conn.getRecentPrioritizationFees();
                const fees = feeHistory.map(f => f.prioritizationFee);
                let suggestedFee;
                if (fees.length === 0) {
                    suggestedFee = 2000;
                } else {
                    fees.sort((a, b) => a - b);
                    suggestedFee = fees[Math.floor(fees.length / 2)];
                }

                // Step D: Update priority fee in TX
                function encodeLE(num, size) {
                    const r = new Uint8Array(size);
                    for (let i = 0; i < size; i++) { r[i] = num & 0xff; num >>= 8; }
                    return r;
                }
                try {
                    const offset = 1;
                    const priceData = tx.message.compiledInstructions[1].data;
                    const encodedPrice = encodeLE(suggestedFee, 8);
                    for (let i = 0; i < encodedPrice.length; i++) priceData[i + offset] = encodedPrice[i];
                    const limitData = tx.message.compiledInstructions[0].data;
                    const encodedLimit = encodeLE(NEW_CU_LIMIT, 4);
                    for (let i = 0; i < encodedLimit.length; i++) limitData[i + offset] = encodedLimit[i];
                } catch (e) { /* non-fatal */ }

                // Step E: Fresh blockhash again + re-sign (official pattern)
                latestBh = await conn.getLatestBlockhash('confirmed');
                tx.message.recentBlockhash = latestBh.blockhash;
                tx.sign([signer]);

                // 4. Submit
                let txSignature = null;
                let submitErr = null;
                try {
                    const raw = tx.serialize();
                    txSignature = await conn.sendRawTransaction(raw, { skipPreflight: false });
                } catch (sendErr) {
                    submitErr = sendErr.message || String(sendErr);
                }

                if (!txSignature) {
                    result = {
                        success: false,
                        error: `TX submit failed: ${submitErr}`,
                        data: {
                            estimation: execData.estimation,
                            order_id: execData.orderId,
                        }
                    };
                    break;
                }

                // 5. Wait for confirmation
                let confirmed = false;
                try {
                    const confirmation = await conn.confirmTransaction({
                        signature: txSignature,
                        blockhash: latestBh.blockhash,
                        lastValidBlockHeight: latestBh.lastValidBlockHeight,
                    }, 'confirmed');
                    confirmed = !confirmation.value.err;
                    if (confirmation.value.err) {
                        result = {
                            success: false,
                            error: `TX failed on-chain: ${JSON.stringify(confirmation.value.err)}`,
                            data: {
                                estimation: execData.estimation,
                                order_id: execData.orderId,
                                tx_signature: txSignature,
                            }
                        };
                        break;
                    }
                } catch (confErr) {
                    confirmed = false;
                }

                result = {
                    success: true,
                    data: {
                        estimation: execData.estimation,
                        order_id: execData.orderId,
                        tx_signature: txSignature,
                        confirmed: confirmed,
                    }
                };
                break;
            }
            case 'resolve-token': {
                // Auto-detect chain + token metadata from contract address
                const { address } = payload;
                if (!address) {
                    result = { success: false, error: 'address required' };
                    break;
                }

                // If not 0x prefix, it's Solana — skip (handled by Rust side)
                if (!address.startsWith('0x')) {
                    result = { success: false, error: 'Not an EVM address. Solana tokens resolved separately.' };
                    break;
                }

                const erc20Abi = [
                    'function symbol() view returns (string)',
                    'function name() view returns (string)',
                    'function decimals() view returns (uint8)',
                ];

                const chains = [
                    { chain_id: 8453, name: 'base', rpc: BASE_RPC_URL },
                    { chain_id: 56, name: 'bsc', rpc: BSC_RPC_URL },
                ];

                const results = await Promise.allSettled(chains.map(async (chain) => {
                    const provider = new ethers.JsonRpcProvider(chain.rpc);
                    const contract = new ethers.Contract(address, erc20Abi, provider);

                    const [symbol, name, decimals, code] = await Promise.all([
                        contract.symbol(),
                        contract.name(),
                        contract.decimals(),
                        provider.getCode(address),
                    ]);

                    // No contract deployed at this address
                    if (!code || code === '0x') {
                        throw new Error('No contract at address');
                    }

                    return {
                        chain_id: chain.chain_id,
                        chain_name: chain.name,
                        address: address,
                        symbol: symbol,
                        name: name,
                        decimals: Number(decimals),
                    };
                }));

                // Collect successful resolutions
                const resolved = [];
                for (const r of results) {
                    if (r.status === 'fulfilled' && r.value) {
                        resolved.push(r.value);
                    }
                }

                if (resolved.length === 0) {
                    result = { success: false, error: 'Token not found on Base or BSC' };
                } else {
                    // Return first match (Base prioritized since it's checked first)
                    result = {
                        success: true,
                        data: resolved[0],
                        all_chains: resolved,
                    };
                }
                break;
            }
            default:
                result = { success: false, error: `Unknown command: ${command}` };
        }

        console.log(JSON.stringify(result));
    } catch (e) {
        console.log(JSON.stringify({ success: false, error: e.message }));
    }
}

main();
