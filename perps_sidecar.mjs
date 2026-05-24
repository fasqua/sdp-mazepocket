#!/usr/bin/env node
/**
 * KausaLayer Perps Sidecar
 * Jupiter Perpetuals integration via Anchor IDL
 * Pattern: stdin JSON payload, stdout JSON response
 * Based on: julianfssen/jupiter-perps-anchor-idl-parsing + diaorui/jupiter-perps-mcp
 */

import { Connection, Keypair, PublicKey, ComputeBudgetProgram, TransactionMessage, VersionedTransaction, SystemProgram } from "@solana/web3.js";
import { getAssociatedTokenAddressSync, createAssociatedTokenAccountIdempotentInstruction, createCloseAccountInstruction, createSyncNativeInstruction, NATIVE_MINT } from "@solana/spl-token";
import { AnchorProvider, Program, Wallet } from "@coral-xyz/anchor";
import BN from "bn.js";
import bs58 from "bs58";
import { IDL } from "./jupiter-perpetuals-idl.mjs";

// ============ CONSTANTS ============

const JUPITER_PERPETUALS_PROGRAM_ID = new PublicKey("PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu");
const JLP_POOL_ACCOUNT_PUBKEY = new PublicKey("5BUwFW4nRbftYTDMbgxykoFWqWHPzahFSNAaaaJtVKsq");
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const PERPS_API_BASE = "https://perps-api.jup.ag/v1";

const TOKENS = {
  SOL: { symbol: "SOL", mint: new PublicKey("So11111111111111111111111111111111111111112"), custodyAccount: new PublicKey("7xS2gz2bTp3fwCC7knJvUWTEU9Tycczu6VhJYKgi1wdz") },
  ETH: { symbol: "ETH", mint: new PublicKey("7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs"), custodyAccount: new PublicKey("AQCGyheWPLeo6Qp9WpYS9m3Qj479t7R636N9ey1rEjEn") },
  BTC: { symbol: "BTC", mint: new PublicKey("3NZ9JMVBmGAqocybic2c7LQCJScmgsAZ6vQqTDzcqmJh"), custodyAccount: new PublicKey("5Pv3gM9JrFFH883SWAhvJC9RPYmo8UNxuFtv5bMMALkm") },
  USDC: { symbol: "USDC", mint: new PublicKey(USDC_MINT), custodyAccount: new PublicKey("G18jKKXQwBbrHeiK3C9MRXhkHsLHf7XgCSisykV46EZa") },
  USDT: { symbol: "USDT", mint: new PublicKey("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"), custodyAccount: new PublicKey("4vkNeXiYEUizLdrpdPS1eC2mccyM4NUPRtERrk6ZETkk") },
};

// ============ HELPERS ============

function getTokenInfo(symbol) {
  const upper = symbol.toUpperCase();
  const token = TOKENS[upper];
  if (!token) throw new Error(`Unsupported token: ${symbol}. Supported: SOL, ETH, BTC`);
  return token;
}

function initializeProgram(connection) {
  const dummyWallet = new Wallet(Keypair.generate());
  const provider = new AnchorProvider(connection, dummyWallet, AnchorProvider.defaultOptions());
  return new Program(IDL, JUPITER_PERPETUALS_PROGRAM_ID, provider);
}

function generatePositionPda({ custody, collateralCustody, walletAddress, side }) {
  const [position] = PublicKey.findProgramAddressSync(
    [Buffer.from("position"), walletAddress.toBuffer(), JLP_POOL_ACCOUNT_PUBKEY.toBuffer(), custody.toBuffer(), collateralCustody.toBuffer(), Buffer.from(side === "long" ? [1] : [2])],
    JUPITER_PERPETUALS_PROGRAM_ID
  );
  return { position };
}

function generatePositionRequestPda({ positionPubkey, requestChange }) {
  const counter = new BN(Math.floor(Math.random() * 1_000_000_000));
  const requestChangeEnum = requestChange === "increase" ? [1] : [2];
  const [positionRequest] = PublicKey.findProgramAddressSync(
    [Buffer.from("position_request"), positionPubkey.toBuffer(), counter.toArrayLike(Buffer, "le", 8), Buffer.from(requestChangeEnum)],
    JUPITER_PERPETUALS_PROGRAM_ID
  );
  return { positionRequest, counter };
}

async function signAndSendTransaction(transaction, connection, signer) {
  transaction.sign([signer]);
  const signature = await connection.sendTransaction(transaction, { preflightCommitment: "confirmed" });
  return signature;
}

// ============ COMMANDS ============

async function cmdOpenPosition(payload) {
  const { private_key, rpc_url, asset, side, collateral_usdc, leverage, priority_fee } = payload;
  const connection = new Connection(rpc_url);
  const walletKeypair = Keypair.fromSecretKey(bs58.decode(private_key));
  const program = initializeProgram(connection);
  const priorityFee = priority_fee || 100000;

  const assetToken = getTokenInfo(asset);
  const assetCustodyPubkey = assetToken.custodyAccount;
  const collateralCustodyPubkey = side === "Long" ? assetCustodyPubkey : getTokenInfo("USDC").custodyAccount;

  const { position: positionPubkey } = generatePositionPda({
    custody: assetCustodyPubkey, collateralCustody: collateralCustodyPubkey,
    walletAddress: walletKeypair.publicKey, side: side === "Long" ? "long" : "short",
  });

  const { positionRequest, counter } = generatePositionRequestPda({ positionPubkey, requestChange: "increase" });

  const inputMint = new PublicKey(USDC_MINT);
  const positionRequestAta = getAssociatedTokenAddressSync(inputMint, positionRequest, true);
  const fundingAccount = getAssociatedTokenAddressSync(inputMint, walletKeypair.publicKey);

  const collateralTokenDelta = new BN(Math.floor(collateral_usdc * 1_000_000));
  const sizeUsd = collateral_usdc * leverage;
  const sizeUsdDelta = new BN(Math.floor(sizeUsd * 1_000_000));

  let jupiterMinimumOut = null;
  if (side === "Long") jupiterMinimumOut = new BN(1);

  const { blockhash } = await connection.getLatestBlockhash("confirmed");

  const sideEnum = side === "Long" ? { long: {} } : { short: {} };
  const increaseIx = await program.methods
    .createIncreasePositionMarketRequest({
      counter, collateralTokenDelta,
      jupiterMinimumOut: jupiterMinimumOut && jupiterMinimumOut.gten(0) ? jupiterMinimumOut : null,
      priceSlippage: side === "Long" ? new BN("18446744073709551615", 10) : new BN("0", 10),
      side: sideEnum, sizeUsdDelta,
    })
    .accounts({
      custody: assetCustodyPubkey, collateralCustody: collateralCustodyPubkey,
      fundingAccount, inputMint, owner: walletKeypair.publicKey,
      perpetuals: PublicKey.findProgramAddressSync([Buffer.from("perpetuals")], JUPITER_PERPETUALS_PROGRAM_ID)[0],
      pool: JLP_POOL_ACCOUNT_PUBKEY, position: positionPubkey,
      positionRequest, positionRequestAta, referral: null,
    })
    .instruction();

  const instructions = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: priorityFee }),
    increaseIx,
  ];

  // Simulate to get accurate compute units
  const simulateTx = new VersionedTransaction(
    new TransactionMessage({ instructions, payerKey: walletKeypair.publicKey, recentBlockhash: blockhash }).compileToV0Message([])
  );
  const simulation = await connection.simulateTransaction(simulateTx, { replaceRecentBlockhash: true, sigVerify: false, commitment: "confirmed" });
  if (simulation.value.err) throw new Error(`Simulation failed: ${JSON.stringify(simulation.value.err)}`);

  let computeUnits = Math.ceil((simulation.value.unitsConsumed || 400000) * 1.2);
  if (computeUnits > 1_400_000) throw new Error(`Compute units ${computeUnits} exceeds limit`);
  instructions[0] = ComputeBudgetProgram.setComputeUnitLimit({ units: computeUnits });

  const txMessage = new TransactionMessage({ payerKey: walletKeypair.publicKey, recentBlockhash: blockhash, instructions }).compileToV0Message();
  const transaction = new VersionedTransaction(txMessage);
  const signature = await signAndSendTransaction(transaction, connection, walletKeypair);

  return { signature, position_pubkey: positionPubkey.toBase58(), side, asset, collateral_usdc, leverage, size_usd: sizeUsd };
}

async function cmdClosePosition(payload) {
  const { private_key, rpc_url, asset, side, priority_fee } = payload;
  const connection = new Connection(rpc_url);
  const walletKeypair = Keypair.fromSecretKey(bs58.decode(private_key));
  const program = initializeProgram(connection);
  const priorityFee = priority_fee || 100000;
  const walletAddress = walletKeypair.publicKey.toBase58();

  // Find position via API
  const positionsResp = await fetch(`${PERPS_API_BASE}/positions?walletAddress=${walletAddress}`);
  if (!positionsResp.ok) throw new Error(`Failed to fetch positions: ${positionsResp.statusText}`);
  const positionsData = await positionsResp.json();

  const targetMint = getTokenInfo(asset).mint.toBase58();
  const matching = positionsData.dataList.filter(p => p.marketMint === targetMint && p.side.toLowerCase() === side.toLowerCase());
  if (matching.length === 0) throw new Error(`No ${side} position found for ${asset}`);

  const positionPubkey = new PublicKey(matching[0].positionPubkey);
  const position = await program.account.position.fetch(positionPubkey, "confirmed");

  const { positionRequest, counter } = generatePositionRequestPda({ positionPubkey, requestChange: "decrease" });
  const desiredMint = new PublicKey(USDC_MINT);
  const positionRequestAta = getAssociatedTokenAddressSync(desiredMint, positionRequest, true);
  const receivingAccount = getAssociatedTokenAddressSync(desiredMint, position.owner, true);

  const { blockhash } = await connection.getLatestBlockhash("confirmed");

  const decreaseIx = await program.methods
    .createDecreasePositionMarketRequest({
      collateralUsdDelta: new BN(0), sizeUsdDelta: new BN(0),
      priceSlippage: position.side.long ? new BN("0", 10) : new BN("18446744073709551615", 10),
      jupiterMinimumOut: null, counter, entirePosition: true,
    })
    .accounts({
      owner: position.owner, receivingAccount,
      perpetuals: PublicKey.findProgramAddressSync([Buffer.from("perpetuals")], JUPITER_PERPETUALS_PROGRAM_ID)[0],
      pool: JLP_POOL_ACCOUNT_PUBKEY, position: positionPubkey,
      positionRequest, positionRequestAta, custody: position.custody,
      collateralCustody: position.collateralCustody, desiredMint, referral: null,
    })
    .instruction();

  const instructions = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: priorityFee }),
    decreaseIx,
  ];

  const simulateTx = new VersionedTransaction(
    new TransactionMessage({ instructions, payerKey: position.owner, recentBlockhash: blockhash }).compileToV0Message([])
  );
  const simulation = await connection.simulateTransaction(simulateTx, { replaceRecentBlockhash: true, sigVerify: false, commitment: "confirmed" });
  if (simulation.value.err) throw new Error(`Simulation failed: ${JSON.stringify(simulation.value.err)}`);

  let computeUnits = Math.ceil((simulation.value.unitsConsumed || 400000) * 1.2);
  if (computeUnits > 1_400_000) throw new Error(`Compute units ${computeUnits} exceeds limit`);
  instructions[0] = ComputeBudgetProgram.setComputeUnitLimit({ units: computeUnits });

  const txMessage = new TransactionMessage({ payerKey: position.owner, recentBlockhash: blockhash, instructions }).compileToV0Message();
  const transaction = new VersionedTransaction(txMessage);
  const signature = await signAndSendTransaction(transaction, connection, walletKeypair);

  return { signature, position_pubkey: positionPubkey.toBase58(), side, asset, closed: true };
}

async function cmdGetPositions(payload) {
  const { wallet_address } = payload;
  const resp = await fetch(`${PERPS_API_BASE}/positions?walletAddress=${wallet_address}`);
  if (!resp.ok) throw new Error(`Failed to fetch positions: ${resp.statusText}`);
  const data = await resp.json();
  return {
    count: data.count,
    positions: data.dataList.map(p => ({
      position_pubkey: p.positionPubkey,
      side: p.side,
      asset_mint: p.marketMint,
      collateral_usd: parseFloat(p.collateralUsd) / 1_000_000,
      size_usd: parseFloat(p.value),
      entry_price: parseFloat(p.entryPrice),
      mark_price: parseFloat(p.markPrice),
      liquidation_price: parseFloat(p.liquidationPrice),
      leverage: parseFloat(p.leverage),
      pnl_usd: parseFloat(p.pnlAfterFeesUsd),
      pnl_pct: parseFloat(p.pnlChangePctAfterFees),
      borrow_fees_usd: parseFloat(p.borrowFeesUsd),
      close_fees_usd: parseFloat(p.closeFeesUsd),
    })),
  };
}

async function cmdGetMarket(payload) {
  const { asset } = payload;
  const token = getTokenInfo(asset);
  const mintStr = token.mint.toBase58();
  const [poolResp, statsResp] = await Promise.all([
    fetch(`${PERPS_API_BASE}/pool-info?mint=${mintStr}`),
    fetch(`${PERPS_API_BASE}/market-stats?mint=${mintStr}`),
  ]);
  if (!poolResp.ok) throw new Error(`Failed to fetch pool info: ${poolResp.statusText}`);
  if (!statsResp.ok) throw new Error(`Failed to fetch market stats: ${statsResp.statusText}`);
  const pool = await poolResp.json();
  const stats = await statsResp.json();
  return {
    asset, price: parseFloat(stats.price),
    price_change_24h: parseFloat(stats.priceChange24H),
    high_24h: parseFloat(stats.priceHigh24H),
    low_24h: parseFloat(stats.priceLow24H),
    volume_24h: parseFloat(stats.volume),
    open_fee_pct: parseFloat(pool.openFeePercent),
    long_borrow_rate_pct: parseFloat(pool.longBorrowRatePercent),
    short_borrow_rate_pct: parseFloat(pool.shortBorrowRatePercent),
    long_utilization_pct: parseFloat(pool.longUtilizationPercent),
    short_utilization_pct: parseFloat(pool.shortUtilizationPercent),
    long_available_liquidity: parseFloat(pool.longAvailableLiquidity),
    short_available_liquidity: parseFloat(pool.shortAvailableLiquidity),
  };
}

async function cmdEstimate(payload) {
  const { wallet_address, asset, side, collateral_usdc, leverage, max_slippage_bps } = payload;
  const token = getTokenInfo(asset);
  const apiSide = side.toLowerCase();
  const collateralMint = apiSide === "long" ? token.mint.toBase58() : USDC_MINT;
  const collateralTokenDelta = Math.floor(collateral_usdc * 1_000_000).toString();
  const resp = await fetch(`${PERPS_API_BASE}/positions/increase`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      walletAddress: wallet_address, marketMint: token.mint.toBase58(),
      inputMint: USDC_MINT, collateralMint, side: apiSide,
      leverage: leverage.toString(), maxSlippageBps: (max_slippage_bps || 200).toString(),
      collateralTokenDelta, includeSerializedTx: false, tpsl: [],
    }),
  });
  if (!resp.ok) throw new Error(`Failed to fetch estimate: ${resp.statusText}`);
  const data = await resp.json();
  return {
    entry_price: parseFloat(data.quote.entryPriceUsd),
    leverage: parseFloat(data.quote.leverage),
    liquidation_price: parseFloat(data.quote.liquidationPriceUsd),
    open_fee_usd: parseFloat(data.quote.openFeeUsd),
    price_impact_fee_usd: parseFloat(data.quote.priceImpactFeeUsd),
    borrow_fee_usd: parseFloat(data.quote.outstandingBorrowFeeUsd),
    position_size_usd: parseFloat(data.quote.positionSizeUsd),
    collateral_usd: parseFloat(data.quote.positionCollateralSizeUsd),
  };
}


// ============ NEW COMMANDS (REST API) ============

async function cmdSetTpsl(payload) {
  const { private_key, rpc_url, position_pubkey, tp_price, sl_price, receive_token } = payload;
  const connection = new Connection(rpc_url);
  const walletKeypair = Keypair.fromSecretKey(bs58.decode(private_key));
  const walletAddress = walletKeypair.publicKey.toBase58();

  const USDC_MINT_ADDR = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
  const tpsl = [];
  if (tp_price) {
    tpsl.push({
      receiveToken: receive_token || "USDC",
      desiredMint: USDC_MINT_ADDR,
      entirePosition: true,
      sizeUsdDelta: "0",
      triggerPrice: Math.floor(tp_price * 1_000_000).toString(),
      requestType: "tp",
    });
  }
  if (sl_price) {
    tpsl.push({
      receiveToken: receive_token || "USDC",
      desiredMint: USDC_MINT_ADDR,
      entirePosition: true,
      sizeUsdDelta: "0",
      triggerPrice: Math.floor(sl_price * 1_000_000).toString(),
      requestType: "sl",
    });
  }
  if (tpsl.length === 0) throw new Error("Must provide tp_price or sl_price");

  const resp = await fetch(`${PERPS_API_BASE}/tpsl`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ owner: walletAddress, positionPubkey: position_pubkey, tpsl }),
  });
  if (!resp.ok) throw new Error(`Failed to set TP/SL: ${resp.statusText}`);
  const data = await resp.json();

  if (data.serializedTxBase64) {
    const tx = VersionedTransaction.deserialize(Buffer.from(data.serializedTxBase64, "base64"));
    tx.sign([walletKeypair]);

    if (data.requireKeeperSignature) {
      const execResp = await fetch(`${PERPS_API_BASE}/transaction/execute`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "create-tpsl", serializedTxBase64: Buffer.from(tx.serialize()).toString("base64") }),
      });
      if (!execResp.ok) throw new Error(`Failed to execute TP/SL tx: ${execResp.statusText}`);
      const execData = await execResp.json();
      return { txid: execData.txid, tpsl_set: tpsl.map(t => t.requestType), position_pubkey };
    } else {
      const signature = await connection.sendTransaction(tx, { preflightCommitment: "confirmed" });
      return { signature, tpsl_set: tpsl.map(t => t.requestType), position_pubkey };
    }
  }

  return { tpsl_requests: data.tpslRequests, position_pubkey };
}

async function cmdCancelTpsl(payload) {
  const { private_key, rpc_url, position_request_pubkey } = payload;
  const connection = new Connection(rpc_url);
  const walletKeypair = Keypair.fromSecretKey(bs58.decode(private_key));

  const resp = await fetch(`${PERPS_API_BASE}/tpsl`, {
    method: "DELETE", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ positionRequestPubkey: position_request_pubkey }),
  });
  if (!resp.ok) throw new Error(`Failed to cancel TP/SL: ${resp.statusText}`);
  const data = await resp.json();

  if (data.serializedTxBase64) {
    const tx = VersionedTransaction.deserialize(Buffer.from(data.serializedTxBase64, "base64"));
    tx.sign([walletKeypair]);

    if (data.requireKeeperSignature) {
      const execResp = await fetch(`${PERPS_API_BASE}/transaction/execute`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "cancel-tpsl", serializedTxBase64: Buffer.from(tx.serialize()).toString("base64") }),
      });
      if (!execResp.ok) throw new Error(`Failed to execute cancel TP/SL: ${execResp.statusText}`);
      const execData = await execResp.json();
      return { txid: execData.txid, cancelled: true };
    } else {
      const signature = await connection.sendTransaction(tx, { preflightCommitment: "confirmed" });
      return { signature, cancelled: true };
    }
  }
  return { cancelled: true };
}

async function cmdLimitOrder(payload) {
  const { private_key, rpc_url, asset, side, input_token, input_amount, leverage, trigger_price } = payload;
  const connection = new Connection(rpc_url);
  const walletKeypair = Keypair.fromSecretKey(bs58.decode(private_key));
  const walletAddress = walletKeypair.publicKey.toBase58();

  const assetUpper = asset.toUpperCase();
  const token = getTokenInfo(assetUpper);
  const apiSide = side.toLowerCase();
  const collateralMint = apiSide === "long" ? token.mint.toBase58() : USDC_MINT;
  const collateralTokenDelta = Math.floor(input_amount * 1_000_000).toString();

  const resp = await fetch(`${PERPS_API_BASE}/orders/limit`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      asset: assetUpper,
      marketMint: token.mint.toBase58(),
      inputToken: (input_token || "USDC").toUpperCase(),
      inputMint: USDC_MINT,
      inputTokenAmount: collateralTokenDelta,
      collateralMint,
      collateralTokenDelta,
      leverage: leverage.toString(),
      side: apiSide,
      triggerPrice: Math.floor(trigger_price * 1_000_000).toString(),
      walletAddress,
      includeSerializedTx: true,
    }),
  });
  if (!resp.ok) throw new Error(`Failed to create limit order: ${resp.statusText}`);
  const data = await resp.json();

  if (data.serializedTxBase64) {
    const tx = VersionedTransaction.deserialize(Buffer.from(data.serializedTxBase64, "base64"));
    tx.sign([walletKeypair]);
    const signature = await connection.sendTransaction(tx, { preflightCommitment: "confirmed" });
    return { signature, position_pubkey: data.positionPubkey, quote: data.quote };
  }
  return { position_pubkey: data.positionPubkey, quote: data.quote };
}

async function cmdPartialClose(payload) {
  const { private_key, rpc_url, position_pubkey, size_usd_delta, collateral_usd_delta, receive_token } = payload;
  const connection = new Connection(rpc_url);
  const walletKeypair = Keypair.fromSecretKey(bs58.decode(private_key));

  const body = {
    positionPubkey: position_pubkey,
    receiveToken: (receive_token || "USDC").toUpperCase(),
    desiredMint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    entirePosition: false,
    collateralUsdDelta: "0",
  };
  if (size_usd_delta) body.sizeUsdDelta = Math.floor(size_usd_delta * 1_000_000).toString();
  if (collateral_usd_delta) body.collateralUsdDelta = Math.floor(collateral_usd_delta * 1_000_000).toString();

  const resp = await fetch(`${PERPS_API_BASE}/positions/decrease`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`Failed to partial close: ${resp.statusText}`);
  const data = await resp.json();

  if (data.serializedTxBase64) {
    const tx = VersionedTransaction.deserialize(Buffer.from(data.serializedTxBase64, "base64"));
    tx.sign([walletKeypair]);

    if (data.requireKeeperSignature) {
      const execResp = await fetch(`${PERPS_API_BASE}/transaction/execute`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "decrease-position", serializedTxBase64: Buffer.from(tx.serialize()).toString("base64") }),
      });
      if (!execResp.ok) throw new Error(`Failed to execute partial close: ${execResp.statusText}`);
      const execData = await execResp.json();
      return { txid: execData.txid, quote: data.quote, position_pubkey };
    } else {
      const signature = await connection.sendTransaction(tx, { preflightCommitment: "confirmed" });
      return { signature, quote: data.quote, position_pubkey };
    }
  }
  return { quote: data.quote, position_pubkey };
}

async function cmdCloseAll(payload) {
  const { private_key, rpc_url } = payload;
  const connection = new Connection(rpc_url);
  const walletKeypair = Keypair.fromSecretKey(bs58.decode(private_key));
  const walletAddress = walletKeypair.publicKey.toBase58();

  const resp = await fetch(`${PERPS_API_BASE}/positions/close-all`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ walletAddress }),
  });
  if (!resp.ok) throw new Error(`Failed to close all: ${resp.statusText}`);
  const data = await resp.json();

  const signatures = [];
  if (data.serializedTxs && data.serializedTxs.length > 0) {
    for (const txData of data.serializedTxs) {
      const tx = VersionedTransaction.deserialize(Buffer.from(txData.serializedTxBase64, "base64"));
      tx.sign([walletKeypair]);
      const sig = await connection.sendTransaction(tx, { preflightCommitment: "confirmed" });
      signatures.push(sig);
    }
  }
  return { signatures, count: signatures.length, closed_all: true };
}

async function cmdTradeHistory(payload) {
  const { wallet_address, asset, side, start, end } = payload;
  let url = `${PERPS_API_BASE}/trades?walletAddress=${wallet_address}`;
  if (asset) {
    const token = getTokenInfo(asset);
    url += `&mint=${token.mint.toBase58()}`;
  }
  if (side) url += `&side=${side.toLowerCase()}`;
  if (start !== undefined) url += `&start=${start}`;
  if (end !== undefined) url += `&end=${end}`;

  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to fetch trades: ${resp.statusText}`);
  const data = await resp.json();
  return {
    count: data.count,
    trades: data.dataList.map(t => ({
      action: t.action,
      asset: t.positionName,
      side: t.side,
      price: parseFloat(t.price),
      size_usd: parseFloat(t.size),
      pnl_usd: parseFloat(t.pnl || "0"),
      pnl_pct: parseFloat(t.pnlPercentage || "0"),
      fee_usd: parseFloat(t.fee || "0"),
      tx_hash: t.txHash,
      time: t.createdTime,
    })),
  };
}

// ============ MAIN ============

const command = process.argv[2];
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const stdinData = Buffer.concat(chunks).toString();
const payload = stdinData.trim() ? JSON.parse(stdinData) : {};

async function main() {
  try {
    let result;
    switch (command) {
      case "open-position": result = await cmdOpenPosition(payload); break;
      case "close-position": result = await cmdClosePosition(payload); break;
      case "get-positions": result = await cmdGetPositions(payload); break;
      case "get-market": result = await cmdGetMarket(payload); break;
      case "estimate": result = await cmdEstimate(payload); break;
      case "set-tpsl": result = await cmdSetTpsl(payload); break;
      case "cancel-tpsl": result = await cmdCancelTpsl(payload); break;
      case "limit-order": result = await cmdLimitOrder(payload); break;
      case "partial-close": result = await cmdPartialClose(payload); break;
      case "close-all": result = await cmdCloseAll(payload); break;
      case "trade-history": result = await cmdTradeHistory(payload); break;
      default:
        console.log(JSON.stringify({ success: false, error: `Unknown command: ${command}` }));
        process.exit(1);
    }
    console.log(JSON.stringify({ success: true, data: result }));
  } catch (e) {
    console.log(JSON.stringify({ success: false, error: e.message }));
  }
}

main();
