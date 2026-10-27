import postgres from "postgres";

const databaseUrl = process.env.DATABASE_URL;
const redisUrl = process.env["REDIS_URL"];
const stripeKey = process.env.STRIPE_SECRET_KEY;
const nodeEnv = process.env.NODE_ENV ?? "development";
const checkoutEnabled = process.env.FEATURE_CHECKOUT === "true";
const region = process.env.DEPLOY_REGION ?? "us-east-1";

if (!databaseUrl || !stripeKey) {
  throw new Error("DATABASE_URL and STRIPE_SECRET_KEY are required");
}

const sql = postgres(databaseUrl);

export const config = {
  databaseUrl,
  redisUrl,
  stripeKey,
  nodeEnv,
  checkoutEnabled,
  region,
  sql,
};
