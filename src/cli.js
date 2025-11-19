#!/usr/bin/env node

import * as path from "path";

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'

import client from './index.js'


// command for component analysis take manifest type and content
const component = {
	command: 'component </path/to/manifest>',
	desc: 'produce component report for manifest path',
	builder: yargs => yargs.positional(
		'/path/to/manifest',
		{
			desc: 'manifest path for analyzing',
			type: 'string',
			normalize: true,
		}
	),
	handler: async args => {
		let manifestName = args['/path/to/manifest']
		let res = await client.componentAnalysis(manifestName)
		console.log(JSON.stringify(res, null, 2))
	}
}
const validateToken = {
	command: 'validate-token <token-provider> [--token-value thevalue]',
	desc: 'Validates input token if authentic and authorized',
	builder: yargs => yargs.positional(
		'token-provider',
		{
			desc: 'the token provider',
			type: 'string',
			choices: ['snyk','oss-index'],
		}
	).options({
		tokenValue: {
			alias: 'value',
			desc: 'the actual token value to be checked',
			type: 'string',
		}
	}),
	handler: async args => {
		let tokenProvider = args['token-provider'].toUpperCase()
		let opts={}
		if(args['tokenValue'] !== undefined && args['tokenValue'].trim() !=="" ) {
			let tokenValue = args['tokenValue'].trim()
			opts[`TRUSTIFY_DA_${tokenProvider}_TOKEN`] = tokenValue
		}
		let res = await client.validateToken(opts)
		console.log(res)
	}
}

// command for image analysis takes OCI image references
const image = {
	command: 'image <image-refs..>',
	desc: 'produce image analysis report for OCI image references',
	builder: yargs => yargs.positional(
		'image-refs',
		{
			desc: 'OCI image references to analyze (one or more)',
			type: 'string',
			array: true,
		}
	).options({
		html: {
			alias: 'r',
			desc: 'Get the report as HTML instead of JSON',
			type: 'boolean',
			conflicts: 'summary'
		},
		summary: {
			alias: 's',
			desc: 'For JSON report, get only the \'summary\'',
			type: 'boolean',
			conflicts: 'html'
		}
	}),
	handler: async args => {
		let imageRefs = args['image-refs']
		if (!Array.isArray(imageRefs)) {
			imageRefs = [imageRefs]
		}
		let html = args['html']
		let summary = args['summary']
		let res = await client.imageAnalysis(imageRefs, html)
		if(summary && !html) {
			let summaries = {}
			for (let [imageRef, report] of Object.entries(res)) {
				for (let provider in report.providers) {
					if (report.providers[provider].sources !== undefined) {
						for (let source in report.providers[provider].sources) {
							if (report.providers[provider].sources[source].summary) {
								if (!summaries[imageRef]) {
									summaries[imageRef] = {};
								}
								if (!summaries[imageRef][provider]) {
									summaries[imageRef][provider] = {};
								}
								summaries[imageRef][provider][source] = report.providers[provider].sources[source].summary
							}
						}
					}
				}
			}
			res = summaries
		}
		console.log(html ? res : JSON.stringify(res, null, 2))
	}
}

// command for stack analysis takes a manifest path
const stack = {
	command: 'stack </path/to/manifest> [--html|--summary]',
	desc: 'produce stack report for manifest path',
	builder: yargs => yargs.positional(
		'/path/to/manifest',
		{
			desc: 'manifest path for analyzing',
			type: 'string',
			normalize: true,
		}
	).options({
		html: {
			alias: 'r',
			desc: 'Get the report as HTML instead of JSON',
			type: 'boolean',
			conflicts: 'summary'
		},
		summary: {
			alias: 's',
			desc: 'For JSON report, get only the \'summary\'',
			type: 'boolean',
			conflicts: 'html'
		}
	}),
	handler: async args => {
		let manifest = args['/path/to/manifest']
		let html = args['html']
		let summary = args['summary']
		let theProvidersSummary = new Map();
		let theProvidersObject ={}
		let res = await client.stackAnalysis(manifest, html)
		if(summary)
		{
			for (let provider in res.providers ) {
				if (res.providers[provider].sources !== undefined) {
					for(let source in res.providers[provider].sources ) {
						if(res.providers[provider].sources[source].summary) {
							theProvidersSummary.set(source,res.providers[provider].sources[source].summary)
						}
					}
				}
			}
			for (let [provider, providerSummary] of theProvidersSummary) {
				theProvidersObject[provider]=providerSummary
			}
		}
		console.log(html ? res : JSON.stringify(
			!html && summary ? theProvidersObject : res,
			null,
			2
		))
	}
}

// parse and invoke the command
yargs(hideBin(process.argv))
	.usage(`Usage: ${process.argv[0].includes("node") ?  path.parse(process.argv[1]).base : path.parse(process.argv[0]).base} {component|stack|image|validate-token}`)
	.command(stack)
	.command(component)
	.command(image)
	.command(validateToken)
	.scriptName('')
	.version(false)
	.demandCommand(1)
	.wrap(null)
	.parse()
