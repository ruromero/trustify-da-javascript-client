import { expect } from 'chai'

import { selectTrustifyDABackend } from '../src/index.js'

const testUrl = 'https://trustify-da.example.com';
const testUrl2 = 'https://dev.trustify-da.example.com';

suite('testing Select Trustify DA Backend function', () => {

	test('When TRUSTIFY_DA_BACKEND_URL is set in environment variable, should return that value', () => {
		process.env['TRUSTIFY_DA_BACKEND_URL'] = testUrl;
		let selectedUrl = selectTrustifyDABackend({});
		expect(selectedUrl).to.be.equals(testUrl);
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
	});

	test('When TRUSTIFY_DA_BACKEND_URL is set in opts (but not in env), should return that value', () => {
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
		let testOpts = {
			'TRUSTIFY_DA_BACKEND_URL': testUrl
		};
		let selectedUrl = selectTrustifyDABackend(testOpts);
		expect(selectedUrl).to.be.equals(testUrl);
	});

	test('When TRUSTIFY_DA_BACKEND_URL is set in both environment and opts, environment variable should take precedence', () => {
		process.env['TRUSTIFY_DA_BACKEND_URL'] = testUrl;
		let testOpts = {
			'TRUSTIFY_DA_BACKEND_URL': testUrl2
		};
		let selectedUrl = selectTrustifyDABackend(testOpts);
		expect(selectedUrl).to.be.equals(testUrl);
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
	});

	test('When TRUSTIFY_DA_BACKEND_URL is not set, should throw error', () => {
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
		expect(() => selectTrustifyDABackend({})).to.throw('TRUSTIFY_DA_BACKEND_URL is unset');
	});

	test('When TRUSTIFY_DA_BACKEND_URL is empty string in environment, should throw error', () => {
		process.env['TRUSTIFY_DA_BACKEND_URL'] = '';
		expect(() => selectTrustifyDABackend({})).to.throw('TRUSTIFY_DA_BACKEND_URL is unset');
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
	});

	test('When TRUSTIFY_DA_BACKEND_URL is empty string in opts, should throw error', () => {
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
		let testOpts = {
			'TRUSTIFY_DA_BACKEND_URL': ''
		};
		expect(() => selectTrustifyDABackend(testOpts)).to.throw('TRUSTIFY_DA_BACKEND_URL is unset');
	});

	test('When TRUSTIFY_DA_BACKEND_URL is null in opts, should throw error', () => {
		delete process.env['TRUSTIFY_DA_BACKEND_URL'];
		let testOpts = {
			'TRUSTIFY_DA_BACKEND_URL': null
		};
		expect(() => selectTrustifyDABackend(testOpts)).to.throw('TRUSTIFY_DA_BACKEND_URL is unset');
	});

}).afterAll(() => {
	delete process.env['TRUSTIFY_DA_BACKEND_URL'];
});
