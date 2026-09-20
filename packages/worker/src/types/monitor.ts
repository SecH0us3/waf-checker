export interface SendEmailBinding {
	send(message: {
		from: string;
		to: string | string[];
		subject: string;
		text?: string;
		html?: string;
		headers?: Record<string, string>;
	}): Promise<void>;
}

export interface WorkerEnv {
	ASSETS: { fetch: typeof fetch };
	SEND_EMAIL?: SendEmailBinding;
	MONITOR_KV?: KVNamespace;
	EMAIL_ENCRYPTION_KEY?: string;
	TURNSTILE_SECRET_KEY?: string;
	DEV_MODE?: string;
}

export type OwnershipMode = 'fast-track' | 'external';
export type SubscriptionStatus = 'PENDING_EMAIL' | 'PENDING_OWNERSHIP' | 'ACTIVE' | 'UNSUBSCRIBED';

export interface BaselineFingerprint {
	wafDetected: string;
	blockedCount: number;
	bypassedCount: number;
	totalCount: number;
	scanHash: string;
	scannedAt: number;
}

export interface PendingVerificationRecord {
	email: string;
	targetUrl: string;
	mode: OwnershipMode;
	ownershipToken?: string;
	createdAt: number;
}

export interface SubscriptionRecord {
	email: string;
	targetUrl: string;
	status: SubscriptionStatus;
	manageToken: string;
	baselineFingerprint?: BaselineFingerprint;
	createdAt: number;
	lastScannedAt?: number;
}

export interface EmailOptions {
	to: string | string[];
	subject: string;
	text?: string;
	html?: string;
	headers?: Record<string, string>;
}
