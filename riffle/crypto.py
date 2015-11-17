
import base64
import bcrypt
import random
import os

from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime

from Crypto.Util import asn1
from Crypto.PublicKey import RSA
from twisted.internet.defer import inlineCallbacks, returnValue

"""
https://github.com/msabramo/pyOpenSSL/blob/master/examples/certgen.py
# Verifying certificates
https://www.v13.gr/blog/?p=303
"""

RSA_KEY_BITS = 1024

# TODO - sha1 is not secure - look up what to use


###########################################################
# Token handling
###########################################################

def generate_token(bits=RSA_KEY_BITS):
    '''
        Generate a random token.

        bits: Number of random bits to use, should be a multiple of 8.

        Returns a string containing the base64 encoding of the random token.
    '''
    rand = os.urandom(bits / 8)
    token = base64.b64encode(rand)
    return token


###########################################################
# Password Handling
###########################################################

def hashPassword(password):
    """
        Use the bcrypt library to salt/hash the password. Return the hashed password
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(str(password), salt)
    return hashed

def checkPassword(raw, hashed):
    """
        Raw input supplied from user compared with the salted/hashed password
        Returns true if they match, false if not
    """
    return bcrypt.hashpw(str(raw), str(hashed)) == hashed



###########################################################
# Public/Private Key Generation
###########################################################
def genKeysPubPriv():
    """
        Generates an assymetric keypair, returns (publickey, privatekey)
    """

    privateKey = RSA.generate(RSA_KEY_BITS)
    publicKey = privateKey.publickey()

    return publicKey, privateKey

def saveKey(key, path):
    """
        Saves a key to a specific location in PEM format.
    """
    pem = key.exportKey()
    with open(path, 'w') as f:
        f.write(pem)


###########################################################
# Signature Handling
###########################################################

def extractSigDataDigest(cert):
    """
        Accepts a certificate, and parses the certificate to find decoded:
            data, hash, and hashing algorithm (digest)
    """
    algo = cert.get_signature_algorithm()
    print 'algo: %s' % algo
    cert_asn1 = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

    der = asn1.DerSequence()
    der.decode(cert_asn1)

    # Signature has three parts
    der_cert = der[0]
    der_algo = der[1]
    der_sig = der[2]

    # The signature is a BIT STRING
    der_sig_in = asn1.DerObject()
    der_sig_in.decode(der_sig)

    sig0 = der_sig_in.payload

    if sig0[0] != '\x00':
        raise Exception('Number of unused bits is strange')

    sig = sig0[1:]
    return sig, der_cert, algo

def load_key_from_file(keyPath, filetype=crypto.FILETYPE_PEM):
    """
        Loads a key from a specific path.
    """
    with open(keyPath, 'rt') as f:
        key = crypto.load_privatekey(filetype, f.read())

    return key

def save_key_to_file(key, keyPath, filetype=crypto.FILETYPE_PEM):
    """
        Saves a key to a specific path.
    """
    open(keyPath, "wt").write(
        crypto.dump_privatekey(filetype, key))

def load_cert_from_file(certPath, filetype=crypto.FILETYPE_PEM):
    """
        Loads a certificate from a specific path.
    """
    with open(certPath, 'rt') as f:
        cert = crypto.load_certificate(filetype, f.read())

    return cert

def save_cert_to_file(cert, certPath, filetype=crypto.FILETYPE_PEM):
    """
        Saves a certificate from a specific path.
    """
    open(certPath, "wt").write(
        crypto.dump_certificate(filetype, cert))


def load_cert_from_buffer(cert_buffer, filetype=crypto.FILETYPE_PEM):
    """
        Loads a certificate from a specific path.
    """
    cert = crypto.load_certificate(filetype, cert_buffer)

    return cert

def verify_CA_cert(rootCert):
    """
        Accepts the root cert, verify
    """
    return verify_cert(rootCert, rootCert)

def verify_cert(ca_cert, other_cert):
    """
        Currently passed in a root certificate and another certificate.
        Loads the certificates, verifies that the otherCert is signed by rootCert

    """
    #TODO - need to check that timestamps are valid, etc

    # Extract the necessary decoded data/sig/sigdigest for verification
    sig, data, digest = extractSigDataDigest(other_cert)

    # TODO - improve commenting here about authenticity, what verify is diong
    try:
        crypto.verify(ca_cert, sig, data, digest)
        print 'cert is valid'
        return True
    except crypto.Error, e:
        print ':( certificate is not valid :('
        return False


def createIssuer(**name):
    """
        Creates a name/info for a certificate
        Args:
                    **name  - The name of subject of request, possible args are:
                                C   - country
                                ST  - state/province
                                L   - locality
                                O   - organization
                                OU  - organizational unit
                                CN  - common name
                                emailAddress - e-mail address
        Returns:    The certificate request in a X509Req object

    """
    issuer = crypto.X509Name(crypto.X509().get_subject())
    for (key, value) in name.items():
        setattr(issuer, key, value)
    return issuer

def createKeyPair(type=crypto.TYPE_RSA, bits=1024):
    """
        Create key pair.

        Args:       type    - Must be TYPE_RSA or TYPE_DSA
                    bits    - Number of bits to use in key, default 1024
        Returns:    The key pair in PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def createCertRequest(pkey, digest='sha1', **name):
    """
        Creates a certificate request.

        Args:       pkey    - the key to associate with the request
                    digest  - Digestion method for signing
                    **name  - The name of subject of request, possible args are:
                                C   - country
                                ST  - state/province
                                L   - locality
                                O   - organization
                                OU  - organizational unit
                                CN  - common name
                                emailAddress - e-mail address
        Returns:    The certificate request in a X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for (key, value) in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req

def createCertificate(req, (issuerCert, issuerKey), serial, (notBefore, notAfter), digest='sha1'):
    """
        Generates a certificate given a certificate request.

        Args:       req         - Certificate request to use
                    issuerCert  - The certicate of the issuer
                    issuerKey   - The private key of the issuer
                    serial      - Serial number for the certificate
                    notBefore   - timestamp (relative to now) when the certificate starts being valid
                    notAfter    - timestamp (relative to now) when the certificate stops being valid
                    digest      - digest method to use for signing, default is md5

        Returns:    The signed certificate in an X509 object
    """
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert

def createCACertificate(k, issuer, serial, (notBefore, notAfter), digest='sha1'):
    """
        Generates a self-signed certificate and saves to a specific location
    """
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuer)
    cert.set_subject(issuer)
    cert.set_pubkey(k)
    cert.add_extensions([
            crypto.X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
            crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
            crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
        ])
    cert.add_extensions([
        crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=cert),
        ])
    cert.sign(k, digest)

    return cert

def createIntermediateCertificate(csr_buffer, CA_CERT_FILE, CA_KEY_FILE):
    print 'createIntermediateCertificate()'

    # Load the certificate request, which contains public key and CN
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_buffer)

    ca_cert = load_cert_from_file(CA_CERT_FILE)
    ca_key = load_key_from_file(CA_KEY_FILE)

    cert = createCertificate(csr, (ca_cert, ca_key), 1000, (0, 10 * 365 * 24 * 60 * 60), digest='sha1')
    return cert


##################### RANDOM UTILS    #################################
def get_cert_key_names(certs_dir, name):
    name_formatted = name.replace('.', '_')
    CERT_FILE = os.path.join(certs_dir, '%s.crt' % name_formatted)
    KEY_FILE = os.path.join(certs_dir, '%s.key' % name_formatted)
    return CERT_FILE, KEY_FILE

def load_cert_key_from_dir(certs_dir, name):
    """
        Given a directory of certs and a domain, loads the proper cert/key.
    """
    cert_file, key_file = get_cert_key_names(certs_dir, name)
    cert = load_cert_from_file(cert_file)
    key = load_key_from_file(key_file)
    return cert, key

##################### CLIENT HELPERS  #################################
# auth related helper functions
def gen_csr(domain):
    """
        Takes in a domain to request access for.
        Generates a certificate request that will be sent to certificate authority to be signed.
    """

    print 'generating csr'
    k = createKeyPair()
    csr = createCertRequest(k, 'sha1', C='US', ST='WI', L='Madison', O='MyExampleCompany', OU='MyExampleApp', CN=domain)

    csrbuffer = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    return csrbuffer, k


def sign_message(privkey, message, hash_type="sha512"):
    return crypto.sign(privkey, message, hash_type)


##################### AUTH HELPERS   ##################################
# auth related helper functions

def gen_ca_cert(certs_dir, domain):
    """
        Generates the root ca_cert
    """
    print 'gen_ca_cert(certs_dir=%s, domain=%s)' % (certs_dir, domain)

    CERT_FILE, KEY_FILE = get_cert_key_names(certs_dir, domain)

    # CREATE A KEY PAIR
    key = createKeyPair()

    issuer = createIssuer(C='US', ST='WI', L='Madison', O='Paradrop Labs', OU='Central Rabric CA', CN=domain)

    cert = createCACertificate(key, issuer, 1000, (0, 10 * 365 * 24 * 60 * 60), digest='sha1')

    # Save the cert and private key to files
    # TODO - finish
    save_cert_to_file(cert, CERT_FILE)
    save_key_to_file(key, KEY_FILE)

    return CERT_FILE, KEY_FILE

def gen_intermediate_cert(certs_dir, authdomain, intdomain):
    CA_CERT_FILE, CA_KEY_FILE = get_cert_key_names(certs_dir, authdomain)
    INT_CERT_FILE, INT_KEY_FILE = get_cert_key_names(certs_dir, intdomain)

    # Generate the csr for the intermediate node
    # NOTE - we can probably do this more efficiently, but for now just get it done
    # So we generate the csr, then sign the csr
    csr_buffer, k = gen_csr(intdomain)

    cert = createIntermediateCertificate(csr_buffer, CA_CERT_FILE, CA_KEY_FILE)

    save_cert_to_file(cert, INT_CERT_FILE)
    save_key_to_file(k, INT_KEY_FILE)

    return INT_CERT_FILE, INT_KEY_FILE


# Simple test code to check if
if __name__ == "__main__":
    rootPath = '../core/certs/rabric.crt'
    otherPath = '../core/certs/client.crt'
    verifyCert(rootPath, otherPath)
