#!/usr/bin/env node

import client from '@trustify-da/trustify-da-javascript-client';
import process from 'node:process';
import type { AnalysisReport } from '@trustify-da/trustify-da-api-model/model/v5/AnalysisReport';

const args = process.argv.slice(2);

if ('stack' === args[0]) {
	// arg[1] = manifest path; arg[2] = is html boolean
	let html = args[2] === 'true'
	let res = await client.stackAnalysis(args[1], html)
	console.log(html ? res as string : JSON.stringify(res as AnalysisReport, null, 2))
	process.exit(0)
}
if ('component' === args[0]) {
	// arg[1] = manifest path
	let res = await client.componentAnalysis(args[1])
	console.log(JSON.stringify(res as AnalysisReport, null, 2))
	process.exit(0)
}

console.log(`unknown action ${args}`)
process.exit(1)
