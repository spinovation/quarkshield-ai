/**
 * One-time Stripe Catalog Setup for QuarkShield Commercial Packages:
 * - Entry: $300/mo ($3,000/yr) — 5 Seats
 * - Scale: $2,500/mo ($25,000/yr) — 50 Seats
 * - Enterprise: $10,000/mo ($100,000/yr) — 250 Seats
 *
 * Usage:
 *   npx ts-node scripts/setup_stripe_products.ts
 */
import Stripe from 'stripe';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(__dirname, '../.env') });

const apiKey = process.env.STRIPE_SECRET_KEY;
if (!apiKey) {
  console.error('STRIPE_SECRET_KEY is not set in environment or server/.env.');
  process.exit(1);
}

const stripe = new Stripe(apiKey);

interface PlanDef {
  tier: string;
  name: string;
  description: string;
  monthlyAmount: number; // in cents
  annualAmount: number;  // in cents
  seats: number;
}

const PLANS: PlanDef[] = [
  {
    tier: 'entry',
    name: 'QuarkShield Entry — PQC Assessment',
    description: '5 Workstation/Server endpoint licenses, executive Quantum Risk Score, and CycloneDX 1.6 CBOM export.',
    monthlyAmount: 30000,
    annualAmount: 300000,
    seats: 5
  },
  {
    tier: 'scale',
    name: 'QuarkShield Scale — Growth Fleet',
    description: 'Up to 50 monitored fleet endpoints, automated cryptographic drift detection, MDM group tokens, real-time alerts.',
    monthlyAmount: 250000,
    annualAmount: 2500000,
    seats: 50
  },
  {
    tier: 'enterprise',
    name: 'QuarkShield Enterprise — Enterprise Pro',
    description: 'Up to 250 hybrid enterprise endpoints, Remote Git scanner, full QS Copilot AI, dedicated tenant subdomain, 2FA.',
    monthlyAmount: 1000000,
    annualAmount: 10000000,
    seats: 250
  }
];

async function main() {
  console.log('🚀 Initializing QuarkShield Stripe Catalog Provisioning...');
  const results: Record<string, { productId: string; monthlyPriceId: string; annualPriceId: string }> = {};

  for (const plan of PLANS) {
    console.log(`Creating Stripe product: ${plan.name}...`);
    const product = await stripe.products.create({
      name: plan.name,
      description: plan.description,
      metadata: { tier: plan.tier, seats: String(plan.seats) }
    });

    const monthlyPrice = await stripe.prices.create({
      product: product.id,
      currency: 'usd',
      unit_amount: plan.monthlyAmount,
      recurring: { interval: 'month' },
      metadata: { tier: plan.tier, billing: 'monthly' }
    });

    const annualPrice = await stripe.prices.create({
      product: product.id,
      currency: 'usd',
      unit_amount: plan.annualAmount,
      recurring: { interval: 'year' },
      metadata: { tier: plan.tier, billing: 'annual' }
    });

    results[plan.tier] = {
      productId: product.id,
      monthlyPriceId: monthlyPrice.id,
      annualPriceId: annualPrice.id
    };

    console.log(`✅ ${plan.name}: product=${product.id} monthly=${monthlyPrice.id} annual=${annualPrice.id}`);
  }

  console.log('\n--- Environment Variables Configuration ---');
  for (const [tier, ids] of Object.entries(results)) {
    const envKey = tier.toUpperCase();
    console.log(`STRIPE_PRICE_${envKey}_MONTHLY=${ids.monthlyPriceId}`);
    console.log(`STRIPE_PRICE_${envKey}_ANNUAL=${ids.annualPriceId}`);
  }
  console.log('\nCatalog successfully created in Stripe test environment!');
}

main().catch((err) => {
  console.error('Failed to create Stripe products:', err);
  process.exit(1);
});
