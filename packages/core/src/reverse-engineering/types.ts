export type ParanoiaLevel = 1 | 2 | 3 | 4;

export type CRSRuleStatus = 'active' | 'disabled' | 'bypassed' | 'unknown';

export interface CRSRuleDefinition {
	ruleId: string;
	name: string;
	category: string;
	paranoiaLevel: ParanoiaLevel;
	anomalyScore: number;
	probePayload: string;
	probeMethod?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'TRACE';
	probeLocation?: 'query' | 'header' | 'body';
	headerName?: string;
	description?: string;
}

export interface CRSAuditItem {
	ruleId: string;
	name: string;
	category: string;
	paranoiaLevel: ParanoiaLevel;
	anomalyScore: number;
	status: CRSRuleStatus;
	probePayload: string;
	statusCode: number | string;
	responseTime: number;
	evidence?: string;
}

export interface BodyLimitResult {
	limitBytes: number | null;
	limitFormatted: string;
	confidence: number;
	detected: boolean;
	bypassPayloadSize?: number;
}

export interface AnomalyScoreResult {
	mode: 'anomaly_scoring' | 'traditional_regex' | 'unknown';
	detectedThreshold: number | null;
	confidence: number;
	details?: string;
}

export interface RateLimitResult {
	detected: boolean;
	thresholdRps: number | null;
	retryAfterSeconds: number | null;
	safeTestedMaxRps: number;
}

export interface ReverseEngineeringReport {
	targetUrl: string;
	crsRules: CRSAuditItem[];
	crsSummary: {
		total: number;
		active: number;
		disabled: number;
		bypassed: number;
		activePercent: number;
	};
	bodyLimit: BodyLimitResult;
	anomalyScore: AnomalyScoreResult;
	rateLimit: RateLimitResult;
	timestamp: string;
}

export interface ReverseEngineeringOptions {
	fetch?: typeof fetch;
	quiet?: boolean;
	color?: boolean;
	isWorker?: boolean;
	skipRateLimit?: boolean;
	skipBodyLimit?: boolean;
	skipAnomalyScore?: boolean;
	maxRpsProbe?: number;
	allowLocal?: boolean;
}
