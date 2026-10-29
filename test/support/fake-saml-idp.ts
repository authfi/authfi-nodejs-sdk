// A fake AuthFI SAML identity provider: it signs the Assertion only (RSA-SHA256, exclusive c14n), as the
// platform does, and can be told to break each rule a service provider must enforce.

import { randomBytes } from 'node:crypto';
import { generate } from 'selfsigned';
import { SignedXml } from 'xml-crypto';

export const BASE = 'https://acme.authfi.io';
export const ENTITY = `${BASE}/saml/metadata`;
export const SP_ENTITY = 'https://app.example.com/saml';
export const ACS = 'https://app.example.com/saml/acs';
export const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const DS = 'http://www.w3.org/2000/09/xmldsig#';

/** A signing key and its self-signed certificate. */
export interface Signer {
  readonly privateKey: string;
  readonly cert: string;
  /** The certificate as bare base64 DER, as metadata carries it. */
  readonly certB64: string;
}

export async function makeSigner(name = 'AuthFI test'): Promise<Signer> {
  const pems = await generate([{ name: 'commonName', value: name }], { keySize: 2048, algorithm: 'sha256' });
  const certB64 = pems.cert.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  return { privateKey: pems.private, cert: pems.cert, certB64 };
}

export function iso(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');
}

export interface ResponseOptions {
  readonly now: number;
  readonly inResponseTo: string | undefined;
  readonly audience?: string;
  readonly recipient?: string;
  readonly destination?: string;
  readonly issuer?: string;
  readonly nameId?: string;
  readonly nameFormat?: string;
  readonly attributes?: Readonly<Record<string, readonly string[]>>;
  readonly notBefore?: number;
  readonly notOnOrAfter?: number;
  readonly confirmNotOnOrAfter?: number;
  readonly assertionId?: string;
  readonly status?: string;
  readonly sign?: 'assertion' | 'response' | 'none';
  /** Sign with SHA-1 for the signature, the digest, or both. */
  readonly weak?: 'signature' | 'digest' | 'both';
  /** Repeat the first attribute. */
  readonly duplicateAttribute?: boolean;
  readonly signer?: Signer;
  readonly tamper?: boolean;
  readonly wrap?: boolean;
  readonly doctype?: boolean;
  /** A Response that carries a status and no assertion, as a failure answer does. */
  readonly bare?: boolean;
}

export class FakeIdp {
  readonly entityId = ENTITY;
  readonly ssoUrl = `${BASE}/saml/sso`;

  private constructor(readonly signer: Signer) {}

  static async create(): Promise<FakeIdp> {
    return new FakeIdp(await makeSigner());
  }

  metadata(
    options: {
      extraCerts?: readonly string[];
      entityId?: string;
      doctype?: boolean;
      use?: string;
      binding?: string;
    } = {},
  ): string {
    const certs = [this.signer.certB64, ...(options.extraCerts ?? [])]
      .map((c) => `<ds:X509Certificate>${c}</ds:X509Certificate>`)
      .join('');
    const prefix = options.doctype ? '<!DOCTYPE x [<!ENTITY e "x">]>' : '';
    return (
      `${prefix}<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="${DS}" ` +
      `entityID="${options.entityId ?? this.entityId}"><md:IDPSSODescriptor ` +
      'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
      `<md:KeyDescriptor use="${options.use ?? 'signing'}"><ds:KeyInfo><ds:X509Data>${certs}</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
      `<md:SingleSignOnService Binding="${options.binding ?? 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'}" ` +
      `Location="${this.ssoUrl}"/></md:IDPSSODescriptor></md:EntityDescriptor>`
    );
  }

  /** The base64 `SAMLResponse` form field. */
  response(o: ResponseOptions): string {
    const aid = o.assertionId ?? `_a${randomBytes(12).toString('hex')}`;
    const rid = `_r${randomBytes(12).toString('hex')}`;
    const issuer = o.issuer ?? this.entityId;
    const recipient = o.recipient ?? ACS;
    const attrs = o.attributes ?? { groups: ['staff'], roles: ['admin'], name: ['Ada L'] };
    const attrXml = Object.entries(attrs)
      .map(
        ([k, vs]) =>
          `<saml:Attribute Name="${k}">${vs.map((v) => `<saml:AttributeValue>${v}</saml:AttributeValue>`).join('')}</saml:Attribute>`,
      )
      .join('');
    const irt = o.inResponseTo === undefined ? '' : ` InResponseTo="${o.inResponseTo}"`;
    const na = iso(o.notOnOrAfter ?? o.now + 300_000);
    const cna = o.confirmNotOnOrAfter === undefined ? na : iso(o.confirmNotOnOrAfter);
    const nb = iso(o.notBefore ?? o.now - 30_000);
    const first = attrXml.slice(0, attrXml.indexOf('</saml:Attribute>') + 17);
    const statement =
      attrXml === ''
        ? ''
        : `<saml:AttributeStatement>${attrXml}${o.duplicateAttribute ? first : ''}</saml:AttributeStatement>`;
    let xml =
      `<samlp:Response xmlns:samlp="${SAMLP}" xmlns:saml="${SAML}" ID="${rid}" Version="2.0" ` +
      `IssueInstant="${iso(o.now)}" Destination="${o.destination ?? recipient}"${irt}>` +
      `<saml:Issuer>${issuer}</saml:Issuer>` +
      `<samlp:Status><samlp:StatusCode Value="${o.status ?? 'urn:oasis:names:tc:SAML:2.0:status:Success'}"/></samlp:Status>` +
      `<saml:Assertion ID="${aid}" Version="2.0" IssueInstant="${iso(o.now)}">` +
      `<saml:Issuer>${issuer}</saml:Issuer>` +
      `<saml:Subject><saml:NameID Format="${o.nameFormat ?? EMAIL_FORMAT}">${o.nameId ?? 'ada@example.com'}</saml:NameID>` +
      '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
      `<saml:SubjectConfirmationData NotOnOrAfter="${cna}" Recipient="${recipient}"${irt}/>` +
      '</saml:SubjectConfirmation></saml:Subject>' +
      `<saml:Conditions NotBefore="${nb}" NotOnOrAfter="${na}"><saml:AudienceRestriction>` +
      `<saml:Audience>${o.audience ?? SP_ENTITY}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
      `<saml:AuthnStatement AuthnInstant="${iso(o.now - 5000)}" SessionIndex="_s1">` +
      '<saml:AuthnContext><saml:AuthnContextClassRef>urn:authfi:acr:pwd</saml:AuthnContextClassRef></saml:AuthnContext>' +
      `</saml:AuthnStatement>${statement}</saml:Assertion></samlp:Response>`;
    if (o.bare) {
      const bare = `<samlp:Response xmlns:samlp="${SAMLP}" xmlns:saml="${SAML}" ID="${rid}" Version="2.0" IssueInstant="${iso(o.now)}"${irt}><saml:Issuer>${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="${o.status ?? ''}"/></samlp:Status></samlp:Response>`;
      return Buffer.from(bare, 'utf8').toString('base64');
    }
    const sign = o.sign ?? 'assertion';
    if (sign !== 'none') xml = this.#sign(xml, sign === 'assertion' ? 'Assertion' : 'Response', o);
    if (o.tamper) xml = xml.replace('ada@example.com', 'mallory@example.com');
    if (o.wrap) {
      const evil = (/<saml:Assertion [\s\S]*<\/saml:Assertion>/.exec(xml)?.[0] ?? '')
        .replace(/<ds:Signature[\s\S]*<\/ds:Signature>/, '')
        .replace(/ID="[^"]*"/, 'ID="_evil"')
        .replace('ada@example.com', 'admin@example.com');
      xml = xml.replace('<samlp:Status>', `${evil}<samlp:Status>`);
    }
    if (o.doctype) xml = `<!DOCTYPE r [<!ENTITY e "x">]>${xml}`;
    return Buffer.from(xml, 'utf8').toString('base64');
  }

  #sign(xml: string, element: 'Assertion' | 'Response', o: ResponseOptions): string {
    const signer = o.signer ?? this.signer;
    const sig = new SignedXml({
      privateKey: signer.privateKey,
      publicCert: signer.cert,
      signatureAlgorithm:
        o.weak === 'signature' || o.weak === 'both'
          ? 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
          : 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    });
    sig.addReference({
      xpath: `//*[local-name(.)='${element}']`,
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ],
      digestAlgorithm:
        o.weak === 'digest' || o.weak === 'both'
          ? 'http://www.w3.org/2000/09/xmldsig#sha1'
          : 'http://www.w3.org/2001/04/xmlenc#sha256',
    });
    sig.computeSignature(xml, {
      prefix: 'ds',
      location: {
        reference: `//*[local-name(.)='${element}']/*[local-name(.)='Issuer']`,
        action: 'after',
      },
    });
    return sig.getSignedXml();
  }
}
