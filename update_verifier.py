from __future__ import print_function

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


class SignedFile(object):
    def __init__(self, zipdata):
        self._comment_size = None
        self._eocd = None
        self._eocd_size = None
        self._footer = None
        self._signed_len = None
        self._signature_start = None
        self.zipdata = zipdata

    @property
    def footer(self):
        if self._footer is not None:
            return self._footer
        self._footer = self.zipdata[-FOOTER_SIZE:]
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
        self._eocd = self.zipdata[-self.eocd_size:]
        return self._eocd

    @property
    def signed_len(self):
        if self._signed_len is not None:
            return self._signed_len
        signed_len = len(self.zipdata) - self.eocd_size + EOCD_HEADER_SIZE - 2
        self._signed_len = signed_len
        return self._signed_len

    def check_valid(self):
        assert self.footer[2] == 255 and self.footer[3] == 255, (
            "Footer has wrong magic")
        assert self.signature_start <= self.comment_size, (
            "Signature start larger than comment")
        assert self.signature_start > FOOTER_SIZE, (
            "Signature inside footer or outside file")
        assert len(self.zipdata) >= self.eocd_size, "EOCD larger than length"
        assert self.eocd[0:4] == bytearray([80, 75, 5, 6]), (
            "EOCD has wrong magic")
        for i in range(0, self.eocd_size-1):
            assert bytearray(self.zipdata[-i:-i+4]) != bytearray(
                [80, 75, 5, 6]), ("Multiple EOCD magics; possible exploit")
        return True

    def verify(self, pubkey):
        self.check_valid()
        message = self.zipdata[0:self.signed_len]
        signature_size = self.signature_start - FOOTER_SIZE
        signature_raw = self.zipdata[-self.signature_start:-self.signature_start+signature_size]
        sig = ContentInfo.load(signature_raw)['content']['signer_infos'][0]
        sig_contents = sig['signature'].contents
        sig_type = DigestAlgorithmId.map(sig['digest_algorithm']['algorithm'].dotted)
        with open(pubkey, 'rb') as keyfile:
            keydata = load_public_key(keyfile.read())
        return rsa_pkcs1v15_verify(keydata, sig_contents, message, sig_type)


def main():
    parser = argparse.ArgumentParser(description='Verifies whole file signed '
                                                 'Android update files')
    parser.add_argument('public_key')
    parser.add_argument('zipfile')
    args = parser.parse_args()

    with open(args.zipfile, 'rb') as zipfile:
        zipdata = zipfile.read()

    signed_file = SignedFile(zipdata)
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
