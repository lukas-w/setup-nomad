import core from '@actions/core'
import tc from '@actions/tool-cache'
import os from 'os'

// Dependencies required for verifying checksum
import axios from 'axios';
import openpgp from 'openpgp';
import crypto from 'crypto';
import fs from 'fs';
import escapeRegExp from 'lodash.escaperegexp';

const tool = 'nomad';
const baseUrl = `https://releases.hashicorp.com/nomad`;

async function verify(version, variant, path) {
	const sumsUrl = `${baseUrl}/${version}/nomad_${version}_SHA256SUMS`;
	const sigUrl = `${sumsUrl}.sig`;
	const {data: sums} = await axios.get(sumsUrl);
	const {data: sig} = await axios.get(sigUrl, {
		responseType: 'arraybuffer',
	});

	await gpgVerify(sums, sig);
	const filename = `nomad_${version}_${variant}.zip`;
	const re = new RegExp(`^([a-f0-9]{64})\\s+${escapeRegExp(filename)}$`, 'm');
	const expectedSum = re.exec(sums)?.[1];
	if (! expectedSum) {
		throw new Error(`SHA256SUMS doesn't contain a sum for filename ${filename}`);
	}

	const sum = await fileHexSha256(path);
	if (expectedSum !== sum) {
		throw new Error(`${filename} has SHA256 digest ${sum}, expected ${expectedSum}`);		
	}
}

async function fileHexSha256(path) {
	return new Promise((resolve, reject) => {
		const hash = crypto.createHash('sha256');
		const stream = fs.createReadStream(path);
		stream.on('error', err => reject(err));
		stream.on('data', chunk => hash.update(chunk));
		stream.on('end', () => resolve(hash.digest('hex')));
	});
}

async function gpgVerify(text, binarySignature)
{
	openpgp.config.rejectMessageHashAlgorithms.delete(openpgp.enums.hash.sha1);
	const keyUrl = 'https://keybase.io/hashicorp/pgp_keys.asc';
	const {data: keyData} = await axios.get(keyUrl);
	const key = await openpgp.readKey({armoredKey: keyData});
	const message = await openpgp.createMessage({text: text});
	const verificationResult = await openpgp.verify({
		message,
		signature: await openpgp.readSignature({binarySignature}),
		verificationKeys: key,
	});
	const { verified, keyID } = verificationResult.signatures[0];
	return verified;
}

async function fetch(version, variant) {
	const url = `${baseUrl}/${version}/nomad_${version}_${variant}.zip`
	const nomadPath = await tc.downloadTool(url);
	await verify(version, variant, nomadPath);
	const extractedPath = await tc.extractZip(nomadPath);
	return await tc.cacheDir(extractedPath, tool, version, variant);
}

try {
	const version = core.getInput('version');

	const platform = {
		'linux': 'linux',
		'darwin': 'darwin',
		'win32': 'windows',
	}[os.platform()];
	if (! platform) {
		throw new Error(`Unsupported platform ${os.platform()}`);
	}

	const arch = {
		'ia32': '386',
		'x64': 'amd64',
		'arm': 'arm',
		'arm64': 'arm64',
	}[os.arch()];
	if (! arch) {
		throw new Error(`Unsupported arch ${os.arch()}`);	
	}

	const variant = `${platform}_${arch}`;
	let path = tc.find(tool, version, variant) || await fetch(version, variant);
	core.addPath(path);
} catch (error) {
	core.setFailed(error.message);
}
