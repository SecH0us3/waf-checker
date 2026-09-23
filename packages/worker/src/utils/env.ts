import { WorkerEnv } from '../types/monitor';

/**
 * Whether this deployment is a development one.
 *
 * Deliberately keyed on an operator-set variable alone. An earlier version also
 * treated a loopback request hostname as proof of local origin, which it is not:
 * on Workers `new URL(request.url).hostname` is derived from the client-supplied
 * Host header, not from the socket, so anything that made "dev" true could be
 * asserted by the caller — and "dev" governs the encryption key, the captcha and
 * whether a verification link is handed straight back in the response.
 *
 * `wrangler dev` sets nothing by itself, so local runs pass DEV_MODE explicitly
 * (see the `simulate:schedule` script and the dev instructions in wrangler.toml).
 */
export function isDevEnvironment(env: WorkerEnv): boolean {
	return env.DEV_MODE === 'true';
}
