/**
 * index.js
 * Node.js REST API for M-Pesa deposits, withdrawals, B2B, reversals, status & balance.
 *
 * Features:
 * - OAuth token caching
 * - C2B (STK Push), B2C, B2B, Reversal
 * - Transaction status & account balance
 * - Webhook stubs
 * - Input validation (Joi)
 * - Rate limiting
 * - Idempotency with lightweight file-based fallback
 * - Logging with secrets redacted
 *
 * .env example:
 * MPESA_ENV=sandbox
 * MPESA_CONSUMER_KEY=
 * MPESA_CONSUMER_SECRET=
 * MPESA_SHORTCODE=
 * MPESA_PASSKEY=
 * MPESA_INITIATOR_NAME=
 * MPESA_SECURITY_CREDENTIAL=
 * MPESA_CALLBACK_HOST=http://yourhost.com
 * PORT=3000
 *
 * Run:
 *  node index.js
 *
 * Health check:
 *  GET /health → { status:"ok" }
 *
 * Example curl (C2B deposit/STK Push):
 * curl -X POST http://localhost:3000/api/payments/deposit \
 *  -H "Content-Type: application/json" \
 *  -d '{ "amount": 1000, "phone": "+254712345678", "accountReference": "INV-1001", "description": "Order 1001", "idempotencyKey": "dep-INV-1001" }'
 *
 * Example curl (B2C withdrawal):
 * curl -X POST http://localhost:3000/api/payments/withdraw \
 *  -H "Content-Type: application/json" \
 *  -d '{ "amount": 500, "phone": "+254712345678", "remarks": "Refund INV-1001", "idempotencyKey": "wd-INV-1001" }'
 */

import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import Joi from "joi";
import helmet from "helmet";
import cors from "cors";
import pino from "pino";
import rateLimit from "express-rate-limit";
import fs from "fs";
import path from "path";

// Load env
dotenv.config();

// Logger setup (secrets redacted)
const logger = pino({
  redact: ["req.headers.authorization", "req.body.phone", "req.body.passkey", "token"],
});

// Environment/config
const {
  MPESA_ENV = "sandbox",
  MPESA_CONSUMER_KEY,
  MPESA_CONSUMER_SECRET,
  MPESA_SHORTCODE,
  MPESA_PASSKEY,
  MPESA_INITIATOR_NAME,
  MPESA_SECURITY_CREDENTIAL,
  MPESA_CALLBACK_HOST,
  PORT = 3000,
} = process.env;

const BASE_URL =
  MPESA_ENV === "production"
    ? "https://api.safaricom.co.ke"
    : "https://sandbox.safaricom.co.ke";

// Lightweight file-based store for idempotency & transactions
const STORE_FILE = path.join(process.cwd(), "store.json");
let store = { idempotency: {}, transactions: {} };
try {
  if (fs.existsSync(STORE_FILE)) store = JSON.parse(fs.readFileSync(STORE_FILE));
} catch (err) {
  console.error("Failed to load store.json, starting fresh.");
}

function saveStore() {
  fs.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2));
}

// Express app
const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors());

// Rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
});
app.use(limiter);

// Health
app.get("/health", (req, res) => res.json({ status: "ok" }));

// Utility: validate phone number
const phoneSchema = Joi.string()
  .pattern(/^\+2547\d{8}$/)
  .required()
  .messages({ "string.pattern.base": "Phone must be in +2547XXXXXXXX format" });

// Utility: OAuth token caching
let oauthToken = null;
let tokenExpiry = 0;

async function getOAuthToken() {
  const now = Date.now();
  if (oauthToken && tokenExpiry > now) return oauthToken;

  const token = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString(
    "base64"
  );
  const resp = await axios.get(`${BASE_URL}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${token}` },
  });
  oauthToken = resp.data.access_token;
  tokenExpiry = now + resp.data.expires_in * 1000 - 5000; // 5s early
  return oauthToken;
}

// Middleware: idempotency check
function idempotencyCheck(req, res, next) {
  const key = req.body.idempotencyKey;
  if (!key) return res.status(400).json({ error: { code: "IDEMPOTENCY_MISSING", message: "idempotencyKey required" } });
  const existing = store.idempotency[key];
  if (existing) return res.status(200).json(existing);
  res.locals.idempotencyKey = key;
  next();
}

// Helper: store idempotent response
function storeIdempotentResponse(key, response) {
  store.idempotency[key] = response;
  saveStore();
}

// ==================== PAYMENT ENDPOINTS ==================== //

// POST /api/payments/deposit (C2B STK Push)
app.post("/api/payments/deposit", idempotencyCheck, async (req, res) => {
  const schema = Joi.object({
    amount: Joi.number().positive().required(),
    phone: phoneSchema,
    accountReference: Joi.string().required(),
    description: Joi.string().allow(""),
    idempotencyKey: Joi.string().required(),
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).json({ error: { code: "INVALID_INPUT", message: error.message } });

  const { amount, phone, accountReference, description } = value;
  const timestamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
  const password = Buffer.from(`${MPESA_SHORTCODE}${MPESA_PASSKEY}${timestamp}`).toString("base64");

  try {
    const token = await getOAuthToken();
    // STK Push request
    const resp = await axios.post(
      `${BASE_URL}/mpesa/stkpush/v1/processrequest`,
      {
        BusinessShortCode: MPESA_SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        TransactionType: "CustomerPayBillOnline",
        Amount: amount,
        PartyA: phone,
        PartyB: MPESA_SHORTCODE,
        PhoneNumber: phone,
        CallBackURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
        AccountReference: accountReference,
        TransactionDesc: description || "Deposit",
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = {
      transactionId: resp.data.CheckoutRequestID,
      status: "PENDING",
      message: resp.data.ResponseDescription,
    };
    storeIdempotentResponse(req.body.idempotencyKey, data);
    store.transactions[data.transactionId] = { status: "PENDING", amount, type: "C2B" };
    saveStore();
    res.status(201).json(data);
  } catch (err) {
    logger.error(err.response?.data || err.message);
    res.status(500).json({ error: { code: "MPESA_ERROR", message: "Failed to initiate deposit" } });
  }
});

// POST /api/payments/withdraw (B2C)
app.post("/api/payments/withdraw", idempotencyCheck, async (req, res) => {
  const schema = Joi.object({
    amount: Joi.number().positive().required(),
    phone: phoneSchema,
    remarks: Joi.string().allow(""),
    occasion: Joi.string().allow(""),
    idempotencyKey: Joi.string().required(),
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).json({ error: { code: "INVALID_INPUT", message: error.message } });

  const { amount, phone, remarks, occasion } = value;

  try {
    const token = await getOAuthToken();
    const resp = await axios.post(
      `${BASE_URL}/mpesa/b2c/v1/paymentrequest`,
      {
        InitiatorName: MPESA_INITIATOR_NAME,
        SecurityCredential: MPESA_SECURITY_CREDENTIAL,
        CommandID: "BusinessPayment",
        Amount: amount,
        PartyA: MPESA_SHORTCODE,
        PartyB: phone,
        Remarks: remarks || "Withdrawal",
        QueueTimeOutURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
        ResultURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
        Occasion: occasion || "",
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = {
      conversationId: resp.data.ConversationID,
      status: "PENDING",
      message: resp.data.ResponseDescription,
    };
    storeIdempotentResponse(req.body.idempotencyKey, data);
    store.transactions[data.conversationId] = { status: "PENDING", amount, type: "B2C" };
    saveStore();
    res.status(201).json(data);
  } catch (err) {
    logger.error(err.response?.data || err.message);
    res.status(500).json({ error: { code: "MPESA_ERROR", message: "Failed to initiate withdrawal" } });
  }
});

// POST /api/payments/b2b
app.post("/api/payments/b2b", idempotencyCheck, async (req, res) => {
  const schema = Joi.object({
    amount: Joi.number().positive().required(),
    sourceShortCode: Joi.string().required(),
    destShortCode: Joi.string().required(),
    accountReference: Joi.string().allow(""),
    remarks: Joi.string().allow(""),
    idempotencyKey: Joi.string().required(),
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).json({ error: { code: "INVALID_INPUT", message: error.message } });

  const { amount, sourceShortCode, destShortCode, accountReference, remarks } = value;

  try {
    const token = await getOAuthToken();
    const resp = await axios.post(
      `${BASE_URL}/mpesa/b2b/v1/paymentrequest`,
      {
        Initiator: MPESA_INITIATOR_NAME,
        SecurityCredential: MPESA_SECURITY_CREDENTIAL,
        CommandID: "BusinessToBusinessTransfer",
        SenderIdentifierType: "4",
        RecieverIdentifierType: "4",
        Amount: amount,
        PartyA: sourceShortCode,
        PartyB: destShortCode,
        AccountReference: accountReference || "",
        Remarks: remarks || "",
        QueueTimeOutURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
        ResultURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = {
      conversationId: resp.data.ConversationID,
      status: "PENDING",
      message: resp.data.ResponseDescription,
    };
    storeIdempotentResponse(req.body.idempotencyKey, data);
    store.transactions[data.conversationId] = { status: "PENDING", amount, type: "B2B" };
    saveStore();
    res.status(201).json(data);
  } catch (err) {
    logger.error(err.response?.data || err.message);
    res.status(500).json({ error: { code: "MPESA_ERROR", message: "Failed to initiate B2B transfer" } });
  }
});

// POST /api/payments/reversal
app.post("/api/payments/reversal", idempotencyCheck, async (req, res) => {
  const schema = Joi.object({
    transactionId: Joi.string().required(),
    amount: Joi.number().positive().required(),
    remarks: Joi.string().allow(""),
    occasion: Joi.string().allow(""),
    idempotencyKey: Joi.string().required(),
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).json({ error: { code: "INVALID_INPUT", message: error.message } });

  const { transactionId, amount, remarks, occasion } = value;

  try {
    const token = await getOAuthToken();
    const resp = await axios.post(
      `${BASE_URL}/mpesa/reversal/v1/request`,
      {
        Initiator: MPESA_INITIATOR_NAME,
        SecurityCredential: MPESA_SECURITY_CREDENTIAL,
        CommandID: "TransactionReversal",
        TransactionID: transactionId,
        Amount: amount,
        ReceiverParty: MPESA_SHORTCODE,
        RecieverIdentifierType: "4",
        QueueTimeOutURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
        ResultURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
        Remarks: remarks || "",
        Occasion: occasion || "",
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = {
      conversationId: resp.data.ConversationID,
      status: "PENDING",
      message: resp.data.ResponseDescription,
    };
    storeIdempotentResponse(req.body.idempotencyKey, data);
    store.transactions[data.conversationId] = { status: "PENDING", amount, type: "REVERSAL" };
    saveStore();
    res.status(202).json(data);
  } catch (err) {
    logger.error(err.response?.data || err.message);
    res.status(500).json({ error: { code: "MPESA_ERROR", message: "Failed to initiate reversal" } });
  }
});

// GET /api/payments/transactions/:id/status
app.get("/api/payments/transactions/:id/status", async (req, res) => {
  const { id } = req.params;
  const tx = store.transactions[id];
  if (!tx) return res.status(404).json({ error: { code: "NOT_FOUND", message: "Transaction not found" } });

  try {
    const token = await getOAuthToken();
    const resp = await axios.post(
      `${BASE_URL}/mpesa/transactionstatus/v1/query`,
      {
        Initiator: MPESA_INITIATOR_NAME,
        SecurityCredential: MPESA_SECURITY_CREDENTIAL,
        CommandID: "TransactionStatusQuery",
        TransactionID: id,
        PartyA: MPESA_SHORTCODE,
        IdentifierType: "4",
        QueueTimeOutURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
        ResultURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json({
      transactionId: id,
      status: resp.data.Result.Status || tx.status,
      amount: tx.amount,
      resultCode: resp.data.Result.ResultCode,
      resultDesc: resp.data.Result.ResultDesc,
    });
  } catch (err) {
    logger.error(err.response?.data || err.message);
    res.status(500).json({ error: { code: "MPESA_ERROR", message: "Failed to query status" } });
  }
});

// GET /api/payments/account/balance
app.get("/api/payments/account/balance", async (req, res) => {
  try {
    const token = await getOAuthToken();
    const resp = await axios.post(
      `${BASE_URL}/mpesa/accountbalance/v1/query`,
      {
        Initiator: MPESA_INITIATOR_NAME,
        SecurityCredential: MPESA_SECURITY_CREDENTIAL,
        CommandID: "AccountBalance",
        PartyA: MPESA_SHORTCODE,
        IdentifierType: "4",
        QueueTimeOutURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
        ResultURL: `${MPESA_CALLBACK_HOST}/webhooks/mpesa/callback`,
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json({
      shortcode: MPESA_SHORTCODE,
      balances: resp.data.Result.Balance || [],
    });
  } catch (err) {
    logger.error(err.response?.data || err.message);
    res.status(500).json({ error: { code: "MPESA_ERROR", message: "Failed to query balance" } });
  }
});

// ==================== WEBHOOKS ==================== //
app.post("/webhooks/mpesa/callback", (req, res) => {
  // TODO: verify origin/signature
  const { ConversationID, ResultCode, ResultDesc } = req.body;
  if (ConversationID && store.transactions[ConversationID]) {
    store.transactions[ConversationID].status = ResultCode === "0" ? "SUCCESS" : "FAILED";
    saveStore();
  }
  res.json({ ok: true });
});

app.post("/webhooks/mpesa/c2b/validation", (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});
app.post("/webhooks/mpesa/c2b/confirmation", (req, res) => {
  res.json({ ok: true });
});

// Start server
app.listen(PORT, () => console.log(`M-Pesa API running on port ${PORT}`));
