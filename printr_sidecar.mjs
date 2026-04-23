#!/usr/bin/env node
import { createPrintrClient, unwrapResult } from '@printr/sdk';

const API_KEY = process.env.PRINTR_API_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhaS1pbnRlZ3JhdGlvbiJ9.PZsqfleSmSiAra8jiN3JZvDSonoawQLnvYRyPHDbtRg';
const BASE_URL = process.env.PRINTR_API_BASE_URL || 'https://api-preview.printr.money';

const client = createPrintrClient({ apiKey: API_KEY, baseUrl: BASE_URL });

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
            case 'quote': {
                result = await client.POST('/print', {
                    body: {
                        name: payload.name,
                        symbol: payload.symbol,
                        description: payload.description,
                        creator_accounts: payload.creator_accounts,
                        chains: payload.chains || ['solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'],
                    }
                });
                break;
            }
            case 'create': {
                // Resolve image: if URL, download and convert to base64
                let resolvedImage = payload.image_url;
                if (resolvedImage && resolvedImage.startsWith('http')) {
                    try {
                        const imgRes = await fetch(resolvedImage);
                        const imgBuf = Buffer.from(await imgRes.arrayBuffer());
                        resolvedImage = imgBuf.toString('base64');
                    } catch (e) {
                        console.log(JSON.stringify({ success: false, error: `Failed to download image: ${e.message}` }));
                        process.exit(0);
                    }
                }
                result = await client.POST('/print', {
                    body: {
                        name: payload.name,
                        symbol: payload.symbol,
                        description: payload.description,
                        image: resolvedImage,
                        image_path: payload.image_path,
                        chains: payload.chains || ['solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'],
                        creator_accounts: payload.creator_accounts,
                        initial_buy: payload.initial_buy,
                    }
                });
                break;
            }
            case 'get-token': {
                result = await client.GET('/tokens/{id}', {
                    params: { path: { id: payload.token_id } }
                });
                break;
            }
            case 'get-deployments': {
                result = await client.GET('/tokens/{id}/deployments', {
                    params: { path: { id: payload.token_id } }
                });
                break;
            }
            case 'sign-submit': {
                const { signAndSubmitSvm } = await import('@printr/sdk/svm');
                try {
                    const submitResult = await signAndSubmitSvm(
                        payload.payload,
                        payload.private_key,
                        payload.rpc_url || undefined
                    );
                    result = { data: submitResult };
                } catch (e) {
                    console.log(JSON.stringify({ success: false, error: `Sign/submit failed: ${e.message}` }));
                    process.exit(0);
                }
                break;
            }
            default:
                console.log(JSON.stringify({ success: false, error: `Unknown command: ${command}` }));
                process.exit(1);
        }

        if (result.data !== undefined) {
            console.log(JSON.stringify({ success: true, data: result.data }));
        } else {
            const errDetail = typeof result.error === 'object' ? JSON.stringify(result.error) : String(result.error);
            console.log(JSON.stringify({ success: false, error: errDetail, status: result.response?.status }));
        }
    } catch (e) {
        console.log(JSON.stringify({ success: false, error: e.message }));
    }
}

main();
