import { createServer, type Server } from 'node:http';
import { z } from 'zod';
import { isFirewallError } from '../core/errors.js';
import type { Logger } from '../core/logger.js';
import { bearer, HttpError, readJsonBody, safeEqual, sendJson } from '../transports/http-util.js';
import type { ApprovalService, ApprovalStatus } from './approval-service.js';

const DecisionBody = z.strictObject({ signature: z.string().min(20).max(4096) });
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STATUSES = new Set<ApprovalStatus | 'all'>(['pending', 'approved', 'denied', 'expired', 'consumed', 'all']);

/**
 * Approval API (bind to loopback / an internal network; put SSO in front if exposed).
 *
 *   GET  /healthz
 *   GET  /v1/approvals?status=pending        admin token  — list (includes arguments)
 *   GET  /v1/approvals/:id                   admin token  — details + challenge to sign
 *   POST /v1/approvals/:id/decisions         {signature}  — Ed25519-signed vote; the signature IS the credential
 *
 * Reading requires the admin token because pending calls expose tool arguments. Voting does not:
 * a vote is only accepted if signed by a registered approver key over this approval's challenge.
 */
export function createApprovalApi(approvals: ApprovalService, adminToken: string, log: Logger): Server {
  return createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://local');
      const parts = url.pathname.split('/').filter(Boolean);
      try {
        if (req.method === 'GET' && url.pathname === '/healthz') return sendJson(res, 200, { ok: true });

        if (parts[0] !== 'v1' || parts[1] !== 'approvals') throw new HttpError(404, 'not found');
        const id = parts[2];
        if (id !== undefined && !UUID_RE.test(id)) throw new HttpError(400, 'invalid approval id');

        if (req.method === 'POST' && id && parts[3] === 'decisions' && parts.length === 4) {
          const body = DecisionBody.safeParse(await readJsonBody(req, 16_384));
          if (!body.success) throw new HttpError(400, 'body must be {"signature": "<compact JWS>"}');
          const result = await approvals.submitDecision(id, body.data.signature);
          return sendJson(res, 200, result);
        }

        const token = bearer(req);
        if (!token || !safeEqual(token, adminToken)) throw new HttpError(401, 'admin token required');

        if (req.method === 'GET' && !id) {
          const status = (url.searchParams.get('status') ?? 'pending') as ApprovalStatus | 'all';
          if (!STATUSES.has(status)) throw new HttpError(400, 'invalid status');
          return sendJson(res, 200, { approvals: await approvals.list(status) });
        }
        if (req.method === 'GET' && id && parts.length === 3) {
          const view = await approvals.get(id);
          if (!view) throw new HttpError(404, 'approval not found');
          return sendJson(res, 200, view);
        }
        throw new HttpError(405, 'method not allowed');
      } catch (err) {
        if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message });
        if (isFirewallError(err)) return sendJson(res, err.httpStatus, { error: err.code, message: err.message });
        log.error('approval api error', { err });
        return sendJson(res, 500, { error: 'internal error' });
      }
    })();
  });
}
