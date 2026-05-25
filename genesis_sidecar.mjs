#!/usr/bin/env node
/**
 * KausaLayer Genesis Sidecar
 * Wrap SOL -> wSOL and deposit to Metaplex Genesis Launch Pool
 * Pattern: stdin JSON, stdout JSON (same as swap_sidecar)
 *
 * Commands:
 *   wrap-and-deposit  - Wrap SOL to wSOL, deposit to Genesis Launch Pool
 *   claim             - Claim tokens from Genesis Launch Pool
 */

import { createUmi } from "@metaplex-foundation/umi-bundle-defaults";
import { mplToolbox, findAssociatedTokenPda, createTokenIfMissing, transferSol, syncNative } from "@metaplex-foundation/mpl-toolbox";
import { genesis, depositLaunchPoolV2, claimLaunchPoolV2, triggerBehaviorsV2, findLaunchPoolBucketV2Pda, findUnlockedBucketV2Pda, swapBondingCurveV2, findBondingCurveBucketV2Pda, SwapDirection, WRAPPED_SOL_MINT } from "@metaplex-foundation/genesis";
import { keypairIdentity, publicKey, sol } from "@metaplex-foundation/umi";

const command = process.argv[2];
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const stdinData = Buffer.concat(chunks).toString();
const payload = stdinData.trim() ? JSON.parse(stdinData) : {};

async function cmdWrapAndDeposit(payload) {
    const { private_key_bytes, rpc_url, genesis_account, mint_address, amount_lamports } = payload;

    const umi = createUmi(rpc_url)
        .use(mplToolbox())
        .use(genesis());

    const keypairBytes = new Uint8Array(private_key_bytes);
    const kp = umi.eddsa.createKeypairFromSecretKey(keypairBytes);
    umi.use(keypairIdentity(kp));

    const genesisAcc = publicKey(genesis_account);
    const baseMint = publicKey(mint_address);
    const [launchPoolBucket] = findLaunchPoolBucketV2Pda(umi, { genesisAccount: genesisAcc, bucketIndex: 0 });

    // Auto-detect token program (Token classic vs Token-2022)
    const TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
    const TOKEN_CLASSIC = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
    const mintAcc = await umi.rpc.getAccount(baseMint);
    const baseTokenProgram = (mintAcc.exists && mintAcc.owner.toString() === TOKEN_2022)
        ? publicKey(TOKEN_2022)
        : publicKey(TOKEN_CLASSIC);

    // Reserve SOL for tx fees
    const reserveForFees = 5_000_000; // 0.005 SOL
    const depositAmount = amount_lamports - reserveForFees;
    if (depositAmount <= 0) {
        return { success: false, error: "Insufficient balance after reserving for fees" };
    }

    // Step 1: Wrap SOL -> wSOL
    const [userWsolAccount] = findAssociatedTokenPda(umi, {
        owner: umi.identity.publicKey,
        mint: WRAPPED_SOL_MINT,
    });

    const wrapSolAmount = Number(depositAmount) / 1_000_000_000;

    // Step 1: Create wSOL ATA + transfer SOL + sync (single tx)
    await createTokenIfMissing(umi, {
        mint: WRAPPED_SOL_MINT,
        owner: umi.identity.publicKey,
        token: userWsolAccount,
    })
        .add(transferSol(umi, {
            destination: userWsolAccount,
            amount: sol(wrapSolAmount),
        }))
        .add(syncNative(umi, { account: userWsolAccount }))
        .sendAndConfirm(umi, { confirm: { commitment: 'confirmed' } });

    // Step 2: Derive ATAs with correct token program
    const [recipientBaseAta] = findAssociatedTokenPda(umi, {
        owner: umi.identity.publicKey,
        mint: baseMint,
        tokenProgramId: baseTokenProgram,
    });

    // Step 3: Deposit to Launch Pool
    const depositResult = await depositLaunchPoolV2(umi, {
        genesisAccount: genesisAcc,
        bucket: launchPoolBucket,
        baseMint,
        baseTokenProgram,
        recipientBaseTokenAccount: recipientBaseAta,
        amountQuoteToken: BigInt(depositAmount),
    }).sendAndConfirm(umi);

    const sig = depositResult.signature
        ? Buffer.from(depositResult.signature).toString("base64")
        : "";

    return {
        success: true,
        tx_signature: sig,
        depositor: umi.identity.publicKey.toString(),
        amount_deposited: depositAmount,
        launch_pool_bucket: launchPoolBucket.toString(),
    };
}

async function cmdClaim(payload) {
    const { private_key_bytes, rpc_url, genesis_account, mint_address } = payload;

    const umi = createUmi(rpc_url)
        .use(mplToolbox())
        .use(genesis());

    const keypairBytes = new Uint8Array(private_key_bytes);
    const kp = umi.eddsa.createKeypairFromSecretKey(keypairBytes);
    umi.use(keypairIdentity(kp));

    const genesisAcc = publicKey(genesis_account);
    const baseMint = publicKey(mint_address);
    const [launchPoolBucket] = findLaunchPoolBucketV2Pda(umi, { genesisAccount: genesisAcc, bucketIndex: 0 });
    const [unlockedBucket] = findUnlockedBucketV2Pda(umi, { genesisAccount: genesisAcc, bucketIndex: 0 });

    // Step 1: Try trigger end behaviors (may already be done)
    try {
        const unlockedBucketQuoteTokenAccount = findAssociatedTokenPda(umi, {
            owner: unlockedBucket,
            mint: WRAPPED_SOL_MINT,
        });

        await triggerBehaviorsV2(umi, {
            genesisAccount: genesisAcc,
            primaryBucket: launchPoolBucket,
            baseMint,
        })
            .addRemainingAccounts([
                { pubkey: unlockedBucket, isSigner: false, isWritable: true },
                { pubkey: publicKey(unlockedBucketQuoteTokenAccount), isSigner: false, isWritable: true },
            ])
            .sendAndConfirm(umi);
    } catch (e) {
        // May already be triggered, continue
    }

    // Step 2: Claim tokens
    const claimResult = await claimLaunchPoolV2(umi, {
        genesisAccount: genesisAcc,
        bucket: launchPoolBucket,
        baseMint,
        recipient: umi.identity.publicKey,
    }).sendAndConfirm(umi);

    const sig = claimResult.signature
        ? Buffer.from(claimResult.signature).toString("base64")
        : "";

    return {
        success: true,
        tx_signature: sig,
        claimed_by: umi.identity.publicKey.toString(),
        token_mint: mint_address,
    };
}

async function cmdBuyBondingCurve(payload) {
    const { private_key_bytes, rpc_url, genesis_account, mint_address, amount_lamports, min_amount_out } = payload;

    const umi = createUmi(rpc_url)
        .use(mplToolbox())
        .use(genesis());

    const keypairBytes = new Uint8Array(private_key_bytes);
    const kp = umi.eddsa.createKeypairFromSecretKey(keypairBytes);
    umi.use(keypairIdentity(kp));

    const genesisAcc = publicKey(genesis_account);
    const baseMint = publicKey(mint_address);
    const [bondingCurveBucket] = findBondingCurveBucketV2Pda(umi, { genesisAccount: genesisAcc, bucketIndex: 0 });

    // Auto-detect token program (Token classic vs Token-2022)
    const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
    const TOKEN_CLASSIC_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
    const mintAccount = await umi.rpc.getAccount(baseMint);
    const baseTokenProgram = (mintAccount.exists && mintAccount.owner.toString() === TOKEN_2022_PROGRAM)
        ? publicKey(TOKEN_2022_PROGRAM)
        : publicKey(TOKEN_CLASSIC_PROGRAM);

    // Reserve SOL for tx fees
    const reserveForFees = 5_000_000; // 0.005 SOL
    const buyAmount = amount_lamports - reserveForFees;
    if (buyAmount <= 0) {
        return { success: false, error: "Insufficient balance after reserving for fees" };
    }

    // Step 1: Create wSOL ATA + transfer SOL + sync (single tx)
    const [userWsolAccount] = findAssociatedTokenPda(umi, {
        owner: umi.identity.publicKey,
        mint: WRAPPED_SOL_MINT,
    });

    const wrapSolAmount = Number(buyAmount) / 1_000_000_000;

    await createTokenIfMissing(umi, {
        mint: WRAPPED_SOL_MINT,
        owner: umi.identity.publicKey,
        token: userWsolAccount,
    })
        .add(transferSol(umi, {
            destination: userWsolAccount,
            amount: sol(wrapSolAmount),
        }))
        .add(syncNative(umi, { account: userWsolAccount }))
        .sendAndConfirm(umi, { confirm: { commitment: "confirmed" } });

    // Step 2: Derive ATAs with correct token program for Token-2022 support
    const [buyerBaseAta] = findAssociatedTokenPda(umi, {
        owner: umi.identity.publicKey,
        mint: baseMint,
        tokenProgramId: baseTokenProgram,
    });
    const [genesisBaseAta] = findAssociatedTokenPda(umi, {
        owner: genesisAcc,
        mint: baseMint,
        tokenProgramId: baseTokenProgram,
    });

    // Step 3: Swap on Bonding Curve (Buy)
    const swapResult = await swapBondingCurveV2(umi, {
        genesisAccount: genesisAcc,
        bucket: bondingCurveBucket,
        baseMint,
        baseTokenProgram,
        baseTokenAccount: buyerBaseAta,
        genesisBaseTokenAccount: genesisBaseAta,
        swapDirection: SwapDirection.Buy,
        amount: BigInt(buyAmount),
        minAmountOutScaled: BigInt(min_amount_out || 0),
    }).sendAndConfirm(umi);

    const sig = swapResult.signature
        ? Buffer.from(swapResult.signature).toString("base64")
        : "";

    return {
        success: true,
        tx_signature: sig,
        buyer: umi.identity.publicKey.toString(),
        amount_spent: buyAmount,
        bonding_curve_bucket: bondingCurveBucket.toString(),
    };
}

async function main() {
    try {
        let result;
        switch (command) {
            case "wrap-and-deposit": result = await cmdWrapAndDeposit(payload); break;
            case "claim": result = await cmdClaim(payload); break;
            case "buy-bonding-curve": result = await cmdBuyBondingCurve(payload); break;
            default:
                console.log(JSON.stringify({ success: false, error: "Unknown command: " + command }));
                process.exit(1);
        }
        console.log(JSON.stringify({ success: true, data: result }));
    } catch (e) {
        console.log(JSON.stringify({ success: false, error: e.message }));
    }
}

main();
