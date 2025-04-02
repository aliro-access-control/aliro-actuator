import os
import sys
from binascii import hexlify

PROJECT_PATH = os.path.join(os.getcwd(), "src/")
sys.path.append(PROJECT_PATH)

from aliro_actuator import Global
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.key import KeyPair, PrivateKey, PublicKey

if __name__ == "__main__":
    Global.logger.info("Enter reader public key (or leave empty to generate a key):")
    reader_public_str = input()
    if reader_public_str == "":
        public_keypair = KeyPair()
        reader_public = public_keypair.get_public_key()
        Global.logger.info(
            "Generated Reader Public key: {}".format(hexlify(reader_public.as_bytes()))
        )
        Global.logger.info(
            "Generated from Reader Private key: {}".format(
                hexlify(public_keypair.get_private_key().as_bytes())
            )
        )
    else:
        reader_public = PublicKey(bytes.fromhex(reader_public_str))
        Global.logger.info(
            "Using Reader Public key: {}".format(hexlify(reader_public.as_bytes()))
        )

    Global.logger.info("Enter issuer private key (or leave empty to generate a key):")
    issuer_private_str = input()
    if issuer_private_str == "":
        issuer_private = PrivateKey()
        Global.logger.info(
            "Generated Issuer Private key: {}".format(
                hexlify(issuer_private.as_bytes())
            )
        )
        issuer_public = issuer_private.generate_public_key()
        Global.logger.info(
            "Generated Issuer Public key: {}".format(hexlify(issuer_public.as_bytes()))
        )
        issuer_generated = True
    else:
        Global.logger.info("Enter issuer public key:")
        issuer_public_str = input()
        issuer_private = PrivateKey(
            bytes.fromhex(issuer_private_str), bytes.fromhex(issuer_public_str)
        )
        issuer_public = PublicKey(bytes.fromhex(issuer_public_str))
        Global.logger.info(
            "Using Issuer Private key: {}".format(hexlify(issuer_private.as_bytes()))
        )
        Global.logger.info(
            "Using Issuer Public key: {}".format(hexlify(issuer_public.as_bytes()))
        )

    issuer_keypair = KeyPair(issuer_private, issuer_public)

    certificate = Certificate.generate(
        key_info_subject_public_key=reader_public.as_bytes(),
        issuer_keypair=issuer_keypair,
        serial_number=bytes.fromhex("010203040506060707080880"),
        issuer=bytes(
            "Thisisaverylongissuernametobeusedforalirocertificationtest", "utf-8"
        ),
        subject=bytes(
            "Thisisaverylongsubjectnametobeusedforalirocertificationtest", "utf-8"
        ),
        validity_not_before=bytes.fromhex("32303235303430313030303030305A"),
        validity_not_after=bytes.fromhex("32303330303430313030303030305A"),
        subject=bytes(
            "Thisisaverylongsubjectnametobeusedforalirocertificationtest", "utf-8"
        ),
    )
    Global.logger.info("Generated certificate: {}".format(hexlify(certificate)))
