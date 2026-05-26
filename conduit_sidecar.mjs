#!/usr/bin/env node
import { Conduit } from "@conduitprotocol/sdk";
import { Keypair, Connection, PublicKey } from "@solana/web3.js";
import bs58 from "bs58";

const API_BASE = process.env.CONDUIT_API_BASE || "https://www.conduitprotocol.net/api";
const RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const USDC_MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

const command = process.argv[2];

// Read payload from stdin
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const stdinData = Buffer.concat(chunks).toString();
const payload = stdinData.trim() ? JSON.parse(stdinData) : {};

async function main() {
    try {
        const conduit = new Conduit({ apiBase: API_BASE, rpcUrl: RPC_URL });

        switch (command) {
            case "discover": {
                const manifest = await conduit.manifest();

                let endpoints = manifest.endpoints || [];
                let apiListings = manifest.apiListings || [];

                if (payload.category) {
                    const cat = payload.category.toLowerCase();
                    endpoints = endpoints.filter(
                        (e) =>
                            (e.capability || "").toLowerCase().includes(cat) ||
                            (e.capabilityName || "").toLowerCase().includes(cat)
                    );
                    apiListings = apiListings.filter(
                        (a) => (a.category || "").toLowerCase().includes(cat)
                    );
                }

                console.log(JSON.stringify({
                    success: true,
                    data: {
                        network: manifest.network,
                        asset: manifest.asset,
                        endpoints: endpoints.map((e) => ({
                            path: e.path,
                            capability: e.capability,
                            capabilityName: e.capabilityName,
                            unit: e.unit,
                            providers: e.providers.map((p) => ({
                                id: p.id,
                                name: p.name,
                                pricePerUnit: p.pricePerUnit,
                            })),
                        })),
                        apiListings: apiListings.map((a) => ({
                            id: a.id,
                            name: a.name,
                            category: a.category,
                            pricePerCall: a.pricePerCall,
                        })),
                        endpointCount: endpoints.length,
                        apiListingCount: apiListings.length,
                    },
                }));
                break;
            }

            case "call": {
                if (!payload.private_key) {
                    console.log(JSON.stringify({ success: false, error: "private_key is required" }));
                    process.exit(0);
                }
                if (payload.resource_id === undefined) {
                    console.log(JSON.stringify({ success: false, error: "resource_id is required" }));
                    process.exit(0);
                }

                const secretKey = bs58.decode(payload.private_key);
                const keypair = Keypair.fromSecretKey(secretKey);
                const connection = new Connection(RPC_URL, "finalized");

                // Re-init conduit with walletKeypair for Ed25519 server-side auth
                const conduitWithWallet = new Conduit({
                    apiBase: API_BASE,
                    rpcUrl: RPC_URL,
                    walletKeypair: keypair,
                });

                const signer = {
                    publicKey: keypair.publicKey,
                    sendTransaction: async (tx, conn, opts) => {
                        tx.sign(keypair);
                        const sig = await conn.sendRawTransaction(tx.serialize(), {
                            skipPreflight: opts?.skipPreflight ?? false,
                            preflightCommitment: opts?.preflightCommitment ?? "confirmed",
                        });
                        return sig;
                    },
                };

                console.error("[sidecar] calling conduit.call with resourceId:", payload.resource_id);
                const result = await conduitWithWallet.call({
                    resourceId: payload.resource_id,
                    payload: payload.payload || {},
                    signer,
                    mint: USDC_MINT,
                });
                console.error("[sidecar] raw result:", JSON.stringify(result));
                console.error("[sidecar] result keys:", Object.keys(result || {}));

                console.log(JSON.stringify({
                    success: true,
                    data: {
                        status: result.status,
                        body: result.body,
                        signature: result.signature,
                    },
                }));
                break;
            }

            default:
                console.log(JSON.stringify({ success: false, error: "Unknown command: " + command }));
                process.exit(1);
        }
    } catch (e) {
        console.log(JSON.stringify({ success: false, error: e.message }));
    }
}

main();
