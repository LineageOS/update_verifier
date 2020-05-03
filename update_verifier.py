from __future__ import print_function

import asn1crypto
import oscrypto
from asn1crypto.cms import ContentInfo
from asn1crypto.algos import DigestAlgorithmId
from oscrypto.asymmetric import rsa_pkcs1v15_verify, load_public_key
from oscrypto.errors import SignatureError

import argparse
import os
import sys
import traceback

FOOTER_SIZE = 6
EOCD_HEADER_SIZE = 22


class SignedZIP(object):
    def __init__(self, filepath):
        self._comment_size = None
        self._eocd = None
        self._eocd_size = None
        self._footer = None
        self._signed_len = None
        self._signature_start = None
        self.filepath = filepath
        self.length = os.path.getsize(filepath)

    @property
    def footer(self):
        if self._footer is not None:
            return self._footer
        with open(self.filepath, 'rb') as zipfile:
            zipfile.seek(-FOOTER_SIZE, os.SEEK_END)
            self._footer = bytearray(zipfile.read())
        return self._footer

    @property
    def comment_size(self):
        if self._comment_size is not None:
            return self._comment_size
        self._comment_size = self.footer[4] + (self.footer[5] << 8)
        return self._comment_size

    @property
    def signature_start(self):
        if self._signature_start is not None:
            return self._signature_start
        self._signature_start = self.footer[0] + (self.footer[1] << 8)
        return self._signature_start

    @property
    def eocd_size(self):
        if self._eocd_size is not None:
            return self._eocd_size
        self._eocd_size = self.comment_size + EOCD_HEADER_SIZE
        return self._eocd_size

    @property
    def eocd(self):
        if self._eocd is not None:
            return self._eocd
        with open(self.filepath, 'rb') as zipfile:
            zipfile.seek(-self.eocd_size, os.SEEK_END)
            eocd = bytearray(zipfile.read(self.eocd_size))
        self._eocd = eocd
        return self._eocd

    @property
    def signed_len(self):
        if self._signed_len is not None:
            return self._signed_len
        signed_len = self.length - self.eocd_size + EOCD_HEADER_SIZE - 2
        self._signed_len = signed_len
        return self._signed_len

    def check_valid(self):
        assert self.footer[2] == 255 and self.footer[3] == 255, (
            "Footer has wrong magic, this file probably isn't signed")
        assert self.signature_start <= self.comment_size, (
            "Signature start larger than comment")
        assert self.signature_start > FOOTER_SIZE, (
            "Signature inside footer or outside file")
        assert self.length >= self.eocd_size, "EOCD larger than length"
        assert self.eocd[0:4] == bytearray([80, 75, 5, 6]), (
            "EOCD has wrong magic")
        with open(self.filepath, 'rb') as zipfile:
            for i in range(0, self.eocd_size - 1):
                zipfile.seek(-i, os.SEEK_END)
                assert bytearray(zipfile.read(4)) != bytearray(
                    [80, 75, 5, 6]), "Multiple EOCD magics; possible exploit"
        return True

    def verify(self, pubkey):
        self.check_valid()
        with open(self.filepath, 'rb') as zipfile:
            zipfile.seek(0, os.SEEK_SET)
            message = zipfile.read(self.signed_len)
            zipfile.seek(-self.signature_start, os.SEEK_END)
            signature_size = self.signature_start - FOOTER_SIZE
            signature_raw = zipfile.read(signature_size)
        sig = ContentInfo.load(signature_raw)['content']['signer_infos'][0]
        sig_contents = sig['signature'].contents
        sig_type = DigestAlgorithmId.map(sig['digest_algorithm']['algorithm'].dotted)
        with open(pubkey, 'rb') as keyfile:
            keydata = load_public_key(keyfile.read())
        return rsa_pkcs1v15_verify(keydata, sig_contents, message, sig_type)


class SignedAttributes(asn1crypto.core.Sequence):
    _fields = [
        ('target', asn1crypto.core.PrintableString),
        ('length', asn1crypto.core.Integer),
    ]

    def to_bytes(self):
        return self._header + self._contents


class CertDetails(asn1crypto.core.Sequence):
    _fields = [
        ('format_version', asn1crypto.core.Integer),
        ('certificate', asn1crypto.x509.Certificate),
        ('algorithm', asn1crypto.x509.SignedDigestAlgorithm),
        ('attributes', SignedAttributes),
        ('signature', asn1crypto.core.OctetString),
    ]


class SignedImage(object):
    def __init__(self, filepath):
        self.filepath = filepath
        self.length = os.path.getsize(filepath)
        self.sig_length = 0
        self.raw_signature = None

    def process(self):
        with open(self.filepath, 'rb') as zipfile:
            magic = zipfile.read(8).decode('ascii')

            kernel_size = self.read_int(zipfile)
            zipfile.seek(4, os.SEEK_CUR)  # kernel_addr
            ramdsk_size = self.read_int(zipfile)
            zipfile.seek(4, os.SEEK_CUR)  # ramdsk_addr
            second_size = self.read_int(zipfile)
            zipfile.seek(8, os.SEEK_CUR)
            page_size = self.read_int(zipfile)
            header_ver = self.read_int(zipfile)

            if header_ver != 0:
                raise NotImplementedError(f"Header versions other than"
                                          f" 0 not supported (got {header_ver})")
            # Ceil to nearest page size
            self.sig_length += self.round_to(kernel_size, page_size)
            self.sig_length += self.round_to(ramdsk_size, page_size)
            self.sig_length += self.round_to(second_size, page_size)

            zipfile.seek(self.sig_length, os.SEEK_SET)
            self.raw_signature = zipfile.read()

    def verify(self, pub_key_path):
        self.process()
        with open(self.filepath, 'rb') as zipfile:
            zipfile.seek(0, os.SEEK_SET)
            signed_portion = zipfile.read(self.sig_length)

        cert_details = CertDetails.load(self.raw_signature)
        pub_key = load_public_key(pub_key_path)
        sig = cert_details['signature']
        signed_portion += cert_details['attributes'].to_bytes()

        return rsa_pkcs1v15_verify(
            pub_key,
            sig.contents,
            signed_portion,
            cert_details['algorithm'].hash_algo
        )

    @staticmethod
    def read_int(file):
        return int.from_bytes(file.read(4), byteorder='little')

    @staticmethod
    def round_to(a, b):
        return a + (b - (a % b))


def main():
    parser = argparse.ArgumentParser(description='Verifies whole file signed '
                                                 'Android update files')
    parser.add_argument('public_key')
    parser.add_argument('zipfile')
    args = parser.parse_args()

    signed_file = SignedZIP(args.zipfile)
    with open(args.zipfile, 'rb') as f:
        try:
            if f.read(8).decode('ascii') == "ANDROID!":
                signed_file = SignedImage(args.zipfile)
        except UnicodeDecodeError as e:
            pass
    try:
        signed_file.verify(args.public_key)
        print("verified successfully", file=sys.stderr)
    except (SignatureError,
            ValueError,
            TypeError,
            OSError) as e:
        traceback.print_exc()
        print("failed verification", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
