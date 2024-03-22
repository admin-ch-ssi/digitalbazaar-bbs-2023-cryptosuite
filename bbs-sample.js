import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as bbsCryptosuite
    from './lib/index.js';
import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import jsigs from 'jsonld-signatures';
import { bls12381MultikeyKeyPair } from './test/mock-data.js';
import { loader } from './test/documentLoader.js';

const documentLoader = loader.build();
const { createSignCryptosuite } = bbsCryptosuite;
const { purposes: { AssertionProofPurpose } } = jsigs;
const publicKeyMultibase = 'zDnaekGZTbQBerwcehBSXLqAg6s55hVEBms1zFy89VHXtJSa9';
const controller = `did:key:${publicKeyMultibase}`;
const keyPair = await Bls12381Multikey.from({ ...bls12381MultikeyKeyPair });

// create the unsigned credential
const unsignedCredential = {
    '@context': [
        'https://www.w3.org/2018/credentials/v1',
        {
            '@protected': true,
            AlumniCredential: 'urn:example:AlumniCredential',
            alumniOf: 'https://schema.org#alumniOf'
        },
        'https://w3id.org/security/data-integrity/v2'
    ],
    id: 'urn:uuid:98c5cffc-efa2-43e3-99f5-01e8ef404be0',
    type: ['VerifiableCredential', 'AlumniCredential'],
    issuer: controller,
    issuanceDate: '2010-01-01T19:23:24Z',
    credentialSubject: {
        id: 'urn:uuid:d58b2365-0951-4373-96c8-e886d61829f2',
        alumniOf: 'Example University'
    }
};

// Create suite
const suite = new DataIntegrityProof({
    signer: keyPair.signer(),
    cryptosuite: createSignCryptosuite({
        mandatoryPointers: [
            '/issuer',
            '/issuanceDate'
        ]
    })
});


// Create signed credential
const signedCredential = await jsigs.sign(unsignedCredential, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader
});

console.log(signedCredential);