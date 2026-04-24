import { execSync } from 'node:child_process'
import os from 'node:os'

let cachedPythonVersion = undefined

function getPythonVersion() {
	if (cachedPythonVersion !== undefined) { return cachedPythonVersion }
	try {
		let out = execSync('python3 -c "import sys; print(f\'{sys.version_info.major}.{sys.version_info.minor}\')"',
			{ timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }).toString().trim()
		cachedPythonVersion = out
	} catch {
		cachedPythonVersion = null
	}
	return cachedPythonVersion
}

/** @returns {Record<string, string>} */
export function getEnvironmentMarkers() {
	let platform = process.platform
	let systemMap = { win32: 'Windows', linux: 'Linux', darwin: 'Darwin' }
	let machine = typeof os.machine === 'function' ? os.machine() : process.arch
	let pyVer = getPythonVersion()
	return {
		sys_platform: platform,
		platform_system: systemMap[platform] || platform,
		os_name: platform === 'win32' ? 'nt' : 'posix',
		platform_machine: machine,
		platform_release: os.release(),
		platform_version: os.version?.() || '',
		python_version: pyVer || '',
		python_full_version: pyVer || '',
		implementation_name: 'cpython',
	}
}

function compareVersions(left, right) {
	let lParts = left.split('.').map(Number)
	let rParts = right.split('.').map(Number)
	let len = Math.max(lParts.length, rParts.length)
	for (let i = 0; i < len; i++) {
		let l = lParts[i] || 0
		let r = rParts[i] || 0
		if (l < r) { return -1 }
		if (l > r) { return 1 }
	}
	return 0
}

function evaluateComparison(variable, op, value, env) {
	let envVal = env[variable]
	if (envVal === undefined || envVal === '') {
		return variable.includes('version') ? true : false
	}

	let isVersion = variable.includes('version')
	if (isVersion) {
		let cmp = compareVersions(envVal, value)
		switch (op) {
		case '==': return cmp === 0
		case '!=': return cmp !== 0
		case '>=': return cmp >= 0
		case '<=': return cmp <= 0
		case '>': return cmp > 0
		case '<': return cmp < 0
		case '~=': {
			let parts = value.split('.')
			parts.pop()
			let prefix = parts.join('.')
			return envVal.startsWith(prefix) && cmp >= 0
		}
		default: return true
		}
	}

	switch (op) {
	case '==': return envVal === value
	case '!=': return envVal !== value
	case 'in': return value.split(',').map(s => s.trim()).includes(envVal)
	case 'not in': return !value.split(',').map(s => s.trim()).includes(envVal)
	default: return envVal === value
	}
}

function parseAtom(expr) {
	let m = expr.match(/^\s*([\w.]+)\s*(~=|!=|==|>=|<=|>|<|not\s+in|in)\s*["']([^"']*)["']\s*$/)
	if (m) { return { variable: m[1], op: m[2].replace(/\s+/g, ' '), value: m[3] } }

	let mReverse = expr.match(/^\s*["']([^"']*)['"]\s*(~=|!=|==|>=|<=|>|<|not\s+in|in)\s*([\w.]+)\s*$/)
	if (mReverse) { return { variable: mReverse[3], op: mReverse[2].replace(/\s+/g, ' '), value: mReverse[1] } }

	return null
}

/**
 * @param {string} markerExpr
 * @returns {boolean}
 */
export function evaluateMarker(markerExpr) {
	if (!markerExpr || !markerExpr.trim()) { return true }
	let env = getEnvironmentMarkers()
	return evaluateExpr(markerExpr.trim(), env)
}

function evaluateExpr(expr, env) {
	let orParts = splitLogical(expr, ' or ')
	if (orParts.length > 1) {
		return orParts.some(part => evaluateExpr(part, env))
	}

	let andParts = splitLogical(expr, ' and ')
	if (andParts.length > 1) {
		return andParts.every(part => evaluateExpr(part, env))
	}

	let trimmed = expr.trim()
	if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
		return evaluateExpr(trimmed.slice(1, -1), env)
	}

	let atom = parseAtom(trimmed)
	if (!atom) { return true }

	return evaluateComparison(atom.variable, atom.op, atom.value, env)
}

function splitLogical(expr, sep) {
	let parts = []
	let depth = 0
	let current = ''
	let i = 0
	while (i < expr.length) {
		if (expr[i] === '(') { depth++ }
		if (expr[i] === ')') { depth-- }
		if (depth === 0 && expr.substring(i, i + sep.length) === sep) {
			parts.push(current)
			current = ''
			i += sep.length
			continue
		}
		current += expr[i]
		i++
	}
	parts.push(current)
	return parts.filter(p => p.trim())
}
