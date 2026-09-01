import { AuditResultItem, calculateAuditStats } from './types';
import { ReverseEngineeringReport } from '../reverse-engineering/types';

export function generateSARIFReport(results: AuditResultItem[], targetUrl?: string, reverseEngineering?: ReverseEngineeringReport): string {
	const stats = calculateAuditStats(results, targetUrl);
	const uniqueCategories = [...new Set(results.map((r) => r.category))];

	const rules = uniqueCategories.map((category) => {
		const ruleId = `WAF-${category.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`;
		return {
			id: ruleId,
			name: `${category} Attack Bypass`,
			shortDescription: {
				text: `WAF failed to block ${category} attack payload`,
			},
			fullDescription: {
				text: `A security test payload for category "${category}" was sent to the target, and the WAF did not block it (returned HTTP status 200).`,
			},
			defaultConfiguration: {
				level: 'error',
			},
			properties: {
				tags: ['security', 'waf', category.toLowerCase()],
				precision: 'high',
			},
		};
	});

	const sarifResults = results
		.filter((r) => r.status === 200 || r.status === '200')
		.map((r) => {
			const ruleId = `WAF-${r.category.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`;
			return {
				ruleId,
				ruleIndex: uniqueCategories.indexOf(r.category),
				level: 'error',
				message: {
					text: `WAF Bypass detected: [${r.category}] attack payload succeeded using ${r.method} method (${r.responseTime}ms). Payload: "${r.payload}"`,
				},
				locations: [
					{
						physicalLocation: {
							artifactLocation: {
								uri: targetUrl || 'https://target.local',
							},
							region: {
								startLine: 1,
								startColumn: 1,
							},
						},
						logicalLocations: [
							{
								name: `${r.method} ${r.category}`,
								kind: 'endpoint',
							},
						],
					},
				],
				properties: {
					method: r.method,
					category: r.category,
					payload: r.payload,
					originalPayload: r.originalPayload,
					status: r.status,
					responseTimeMs: r.responseTime,
					bypassTechnique: r.bypassTechnique || 'Standard',
					detectedWAF: r.wafType || stats.detectedWAF,
				},
			};
		});

	const sarifDoc: any = {
		$schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
		version: '2.1.0',
		runs: [
			{
				tool: {
					driver: {
						name: 'WAF-Checker',
						version: '1.0.0',
						informationUri: 'https://github.com/SecH0us3/waf-checker',
						rules,
					},
				},
				results: sarifResults,
				invocations: [
					{
						executionSuccessful: true,
						endTimeUtc: new Date().toISOString(),
					},
				],
			},
		],
	};

	if (reverseEngineering) {
		sarifDoc.runs[0].properties = { reverseEngineering };
	}

	return JSON.stringify(sarifDoc, null, 2);
}
