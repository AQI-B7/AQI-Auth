import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Stripe-style signed webhook envelope:
 *   header: "t=<unix_seconds>,v1=<hex hmac-sha256>"
 *   signed content: `${timestamp}.${rawBody}`
 *
 * Verifying the timestamp defends against replay of a captured payload;
 * the HMAC (over secret only known to us + the receiving tenant) proves
 * the payload came from us and wasn't tampered with in transit.
 */
export function signWebhookPayload(
  secret: string,
  timestamp: number,
  rawBody: string,
): string {
  const signedPayload = `${timestamp}.${rawBody}`;
  const hmac = createHmac('sha256', secret).update(signedPayload).digest('hex');
  return `t=${timestamp},v1=${hmac}`;
}

export function verifyWebhookSignature(
  secret: string,
  header: string,
  rawBody: string,
  toleranceSeconds = 300,
): boolean {
  const parts = Object.fromEntries(
    header.split(',').map((kv) => kv.split('=') as [string, string]),
  );
  const timestamp = Number(parts.t);
  const signature = parts.v1;
  if (!timestamp || !signature) return false;

  if (Math.abs(Date.now() / 1000 - timestamp) > toleranceSeconds) {
    return false;
  }

  const expected = createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  const actualBuf = Buffer.from(signature, 'hex');
  if (expectedBuf.length !== actualBuf.length) return false;
  return timingSafeEqual(expectedBuf, actualBuf);
}
