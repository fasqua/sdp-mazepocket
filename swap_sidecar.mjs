#!/usr/bin/env node
/**
 * KausaLayer Swap Sidecar
 * Sign and execute Jupiter Ultra swap transactions
 * Pattern: stdin JSON, stdout JSON (same as perps_sidecar)
 */

import { Connection, Keypair, VersionedTransaction } from "@solana/web3.js";
import bs58 from "bs58";

const command = process.argv[2];
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const stdinData = Buffer.concat(chunks).toString();
const payload = stdinData.trim() ? JSON.parse(stdinData) : {};

async function cmdSignExecute(payload) {
  const { private_key, transaction_base64, request_id, api_key } = payload;

  // 1. Deserialize TX
  const walletKeypair = Keypair.fromSecretKey(bs58.decode(private_key));
  const txBuffer = Buffer.from(transaction_base64, "base64");
  const transaction = VersionedTransaction.deserialize(txBuffer);

  // 2. Sign
  transaction.sign([walletKeypair]);

  // 3. Serialize signed TX to base64
  const signedTransaction = Buffer.from(transaction.serialize()).toString("base64");

  // 4. Submit via Jupiter /execute
  const resp = await fetch("https://api.jup.ag/ultra/v1/execute", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": api_key || "",
    },
    body: JSON.stringify({ signedTransaction, requestId: request_id }),
  });

  const data = await resp.json();

  if (data.status === "Success") {
    return {
      success: true,
      tx_signature: data.transactionId || data.signature || "",
      status: data.status,
      in_amount: data.inputAmountResult || "",
      out_amount: data.outputAmountResult || "",
    };
  } else {
    return {
      success: false,
      tx_signature: data.transactionId || data.signature || "",
      status: data.status || "Failed",
      error: data.error || JSON.stringify(data),
    };
  }
}

async function main() {
  try {
    let result;
    switch (command) {
      case "sign-execute": result = await cmdSignExecute(payload); break;
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
