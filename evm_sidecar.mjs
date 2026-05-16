#!/usr/bin/env node
import { ethers } from 'ethers';

const BASE_RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
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
                // Get ETH balance + ERC-20 token balances on Base
                const provider = new ethers.JsonRpcProvider(BASE_RPC_URL);
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

                // If token addresses provided, fetch their balances
                if (payload.tokens && Array.isArray(payload.tokens)) {
                    const erc20Abi = ['function balanceOf(address) view returns (uint256)', 'function symbol() view returns (string)', 'function decimals() view returns (uint8)'];
                    for (const tokenAddr of payload.tokens) {
                        try {
                            const contract = new ethers.Contract(tokenAddr, erc20Abi, provider);
                            const [balance, symbol, decimals] = await Promise.all([
                                contract.balanceOf(address),
                                contract.symbol().catch(() => 'UNKNOWN'),
                                contract.decimals().catch(() => 18),
                            ]);
                            balanceData.tokens.push({
                                address: tokenAddr,
                                symbol,
                                decimals: Number(decimals),
                                balance: ethers.formatUnits(balance, decimals),
                                balance_raw: balance.toString(),
                            });
                        } catch (e) {
                            balanceData.tokens.push({
                                address: tokenAddr,
                                symbol: 'ERROR',
                                balance: '0',
                                error: e.message,
                            });
                        }
                    }
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
                // Get quote + create-tx from deBridge DLN API (Base → Solana)
                const {
                    src_token_in,       // 0x... Base token to sell
                    src_amount,         // amount in token's smallest unit
                    dst_recipient,      // pocket Solana pubkey
                    src_authority,      // pocket EVM address
                    dst_authority,      // pocket Solana pubkey
                    affiliate_fee_percent,
                    affiliate_fee_recipient,
                    referral_code,
                } = payload;

                const params = new URLSearchParams({
                    srcChainId: '8453',
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
                // Approve ERC-20 token + send deBridge tx on Base
                // Required for reverse flow: sell Base token -> SOL
                const { private_key, approve_to, approve_token, approve_amount, tx_to, tx_data, tx_value } = payload;

                const provider = new ethers.JsonRpcProvider(BASE_RPC_URL);
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
            default:
                result = { success: false, error: `Unknown command: ${command}` };
        }

        console.log(JSON.stringify(result));
    } catch (e) {
        console.log(JSON.stringify({ success: false, error: e.message }));
    }
}

main();
