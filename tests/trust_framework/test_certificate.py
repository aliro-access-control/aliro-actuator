# Copyright 2023 NXP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
from binascii import hexlify

from cryptography import x509

from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.errors import CertificateDecodingError
from aliro_actuator.trust_framework.key import KeyPair, PublicKey


class Test_Certificate(unittest.TestCase):
    def test_decode_reference(self) -> None:
        encoded = bytes.fromhex(
            (
                "308201523081f9a003020102020101300a06082a8648ce3d0403023011310f300d0603"
                "5504030c06697373756572301e170d3230303130313030303030305a170d3439303130"
                "313030303030305a30123110300e06035504030c077375626a6563743059301306072a"
                "8648ce3d020106082a8648ce3d03010703420004842242f6182ba1c1138d32b77fb9f7"
                "f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59"
                "251d45243ac8544a665cb951422fa341303f301f0603551d230418301680142318e556"
                "71f08eae212142a817720fb817ee93bf300c0603551d130101ff04023000300e060355"
                "1d0f0101ff040403020780300a06082a8648ce3d04030203480030450221008720a2f0"
                "8626d56b7814b7e5bbe04381e1834cf9a2a5d4c85c76783607a22cc60220236a4b757c"
                "d497c8570e84fa3221be99f6c78cc7cbc71d7328aa99be03f1eccf"
            )
        )

        certificate = Certificate.decode(encoded)

        self.assertEqual(certificate.serial_number, bytes.fromhex("01"))
        self.assertEqual(certificate.issuer, bytes.fromhex("697373756572"))
        self.assertEqual(
            certificate.validity_not_before, bytes.fromhex("3230303130313030303030305A")
        )
        self.assertEqual(
            certificate.validity_not_after, bytes.fromhex("3439303130313030303030305A")
        )
        self.assertEqual(certificate.subject, bytes.fromhex("7375626a656374"))
        self.assertEqual(
            certificate.key_info_subject_public_key,
            bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )
        self.assertEqual(
            certificate.signature,
            bytes.fromhex(
                (
                    "0030450221008720a2f08626d56b7814b7e5bbe04381e1834cf9a2a5d4c85c7678"
                    "3607a22cc60220236a4b757cd497c8570e84fa3221be99f6c78cc7cbc71d7328aa"
                    "99be03f1eccf"
                )
            ),
        )

    def test_decode_customized_fields(self) -> None:
        encoded = bytes.fromhex(
            (
                "308201643082010aa003020102020604278ba9fd71300a06082a8648ce3d040302301d"
                "311b301906035504030c12637573746f6d20697373756572206e616d65301e170d3230"
                "303130313030303030305a170d3235303530353030303030305a30123110300e060355"
                "04030c077375626a6563743059301306072a8648ce3d020106082a8648ce3d03010703"
                "420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36"
                "490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422fa34130"
                "3f301f0603551d230418301680142318e55671f08eae212142a817720fb817ee93bf30"
                "0c0603551d130101ff04023000300e0603551d0f0101ff040403020780300a06082a86"
                "48ce3d040302034800304502206080fed25cf442226d5017c0e3f5f929ff5cbd18bfa7"
                "53cbd876c02f0a8abbb4022100bc3e990a9cec57b1c1717fdeb6aab55cece7c96fff47"
                "bf5a7236accfb378347e"
            )
        )

        certificate = Certificate.decode(encoded)

        self.assertEqual(certificate.serial_number, bytes.fromhex("04278ba9fd71"))
        self.assertEqual(
            certificate.issuer, bytes.fromhex("637573746f6d20697373756572206e616d65")
        )
        self.assertEqual(
            certificate.validity_not_before, bytes.fromhex("3230303130313030303030305a")
        )
        self.assertEqual(
            certificate.validity_not_after, bytes.fromhex("3235303530353030303030305a")
        )
        self.assertEqual(certificate.subject, bytes.fromhex("7375626a656374"))
        self.assertEqual(
            certificate.key_info_subject_public_key,
            bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )
        self.assertEqual(
            certificate.signature,
            bytes.fromhex(
                (
                    "00304502206080fed25cf442226d5017c0e3f5f929ff5cbd18bfa753cbd876c02f"
                    "0a8abbb4022100bc3e990a9cec57b1c1717fdeb6aab55cece7c96fff47bf5a7236"
                    "accfb378347e"
                )
            ),
        )

    def test_encode_reference(self) -> None:
        cert = Certificate(
            signature=bytes.fromhex(
                (
                    "0030450221008720a2f08626d56b7814b7e5bbe04381e1834cf9a2a5d4c85c7678"
                    "3607a22cc60220236a4b757cd497c8570e84fa3221be99f6c78cc7cbc71d7328aa"
                    "99be03f1eccf"
                )
            ),
            key_info_subject_public_key=bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )

        encoded = bytes.fromhex(
            (
                "308201523081f9a003020102020101300a06082a8648ce3d0403023011310f300d0603"
                "5504030c06697373756572301e170d3230303130313030303030305a170d3439303130"
                "313030303030305a30123110300e06035504030c077375626a6563743059301306072a"
                "8648ce3d020106082a8648ce3d03010703420004842242f6182ba1c1138d32b77fb9f7"
                "f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59"
                "251d45243ac8544a665cb951422fa341303f301f0603551d230418301680142318e556"
                "71f08eae212142a817720fb817ee93bf300c0603551d130101ff04023000300e060355"
                "1d0f0101ff040403020780300a06082a8648ce3d04030203480030450221008720a2f0"
                "8626d56b7814b7e5bbe04381e1834cf9a2a5d4c85c76783607a22cc60220236a4b757c"
                "d497c8570e84fa3221be99f6c78cc7cbc71d7328aa99be03f1eccf"
            )
        )
        issuer_key = PublicKey(
            bytes.fromhex(
                "04793e3a8f20428d54e7318046d75d05a8737eb6e074e5146a207bff62dae90e24039f"
                "372814a312c3cb82a5a97bb5bfa9e623a3cc886b09dc13d53ef0da7de7bd"
            )
        )

        self.assertEqual(cert.encode(issuer_key), encoded)

    def test_encode_customized_fields(self) -> None:
        cert = Certificate(
            serial_number=bytes.fromhex("04278ba9fd71"),
            signature=bytes.fromhex(
                (
                    "00304502206080fed25cf442226d5017c0e3f5f929ff5cbd18bfa753cbd876c02f"
                    "0a8abbb4022100bc3e990a9cec57b1c1717fdeb6aab55cece7c96fff47bf5a7236"
                    "accfb378347e"
                )
            ),
            issuer=bytes.fromhex("637573746f6d20697373756572206e616d65"),
            validity_not_before=bytes.fromhex("3230303130313030303030305A"),
            validity_not_after=bytes.fromhex("3235303530353030303030305A"),
            subject=bytes.fromhex("7375626a656374"),
            key_info_subject_public_key=bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )

        encoded = bytes.fromhex(
            (
                "308201643082010aa003020102020604278ba9fd71300a06082a8648ce3d040302301d"
                "311b301906035504030c12637573746f6d20697373756572206e616d65301e170d3230"
                "303130313030303030305a170d3235303530353030303030305a30123110300e060355"
                "04030c077375626a6563743059301306072a8648ce3d020106082a8648ce3d03010703"
                "420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36"
                "490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422fa34130"
                "3f301f0603551d230418301680142318e55671f08eae212142a817720fb817ee93bf30"
                "0c0603551d130101ff04023000300e0603551d0f0101ff040403020780300a06082a86"
                "48ce3d040302034800304502206080fed25cf442226d5017c0e3f5f929ff5cbd18bfa7"
                "53cbd876c02f0a8abbb4022100bc3e990a9cec57b1c1717fdeb6aab55cece7c96fff47"
                "bf5a7236accfb378347e"
            )
        )

        issuer_key = PublicKey(
            bytes.fromhex(
                "04793e3a8f20428d54e7318046d75d05a8737eb6e074e5146a207bff62dae90e24039f"
                "372814a312c3cb82a5a97bb5bfa9e623a3cc886b09dc13d53ef0da7de7bd"
            )
        )

        self.assertEqual(cert.encode(issuer_key), encoded)

    def test_encode_compressed(self) -> None:
        cert = Certificate(
            serial_number=bytes.fromhex("04278ba9fd71"),
            signature=bytes.fromhex(
                (
                    "00304502206080fed25cf442226d5017c0e3f5f929ff5cbd18bfa753cbd876c02f"
                    "0a8abbb4022100bc3e990a9cec57b1c1717fdeb6aab55cece7c96fff47bf5a7236"
                    "accfb378347e"
                )
            ),
            issuer=bytes.fromhex("637573746f6d20697373756572206e616d65"),
            validity_not_before=bytes.fromhex("3230303130313030303030305A"),
            validity_not_after=bytes.fromhex("3235303530353030303030305A"),
            subject=bytes.fromhex("7375626a656374"),
            key_info_subject_public_key=bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )
        result = cert.encode_compressed()

        self.assertEqual(
            result,
            bytes.fromhex(
                (
                    "3081c0040200003081b9800604278ba9fd718112637573746f6d20697373756572"
                    "206e616d65830d3235303530353030303030305a85420004842242f6182ba1c113"
                    "8d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acf"
                    "c3401c3a4f4e5a59251d45243ac8544a665cb951422f864800304502206080fed2"
                    "5cf442226d5017c0e3f5f929ff5cbd18bfa753cbd876c02f0a8abbb4022100bc3e"
                    "990a9cec57b1c1717fdeb6aab55cece7c96fff47bf5a7236accfb378347e"
                )
            ),
        )

    def test_encode_compressed_customized_fields(self) -> None:
        cert = Certificate(
            serial_number=bytes.fromhex("04278ba9fd71"),
            issuer=bytes.fromhex("637573746f6d20697373756572206e616d65"),
            validity_not_before=bytes.fromhex("3230303130313030303030305a"),
            validity_not_after=bytes.fromhex("3235303530353030303030305a"),
            subject=bytes.fromhex("7375626a656374"),
            signature=bytes.fromhex(
                (
                    "00304502206080fed25cf442226d5017c0e3f5f929ff5cbd18bfa753cbd876c02f"
                    "0a8abbb4022100bc3e990a9cec57b1c1717fdeb6aab55cece7c96fff47bf5a7236"
                    "accfb378347e"
                )
            ),
            key_info_subject_public_key=bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )
        result = cert.encode_compressed()

        self.assertEqual(
            hexlify(result),
            hexlify(
                bytes.fromhex(
                    (
                        "3081c0040200003081b9800604278ba9fd718112637573746f6d2069737375"
                        "6572206e616d65830d3235303530353030303030305a85420004842242f618"
                        "2ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95"
                        "f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f864800"
                        "304502206080fed25cf442226d5017c0e3f5f929ff5cbd18bfa753cbd876c0"
                        "2f0a8abbb4022100bc3e990a9cec57b1c1717fdeb6aab55cece7c96fff47bf"
                        "5a7236accfb378347e"
                    )
                )
            ),
        )

    def test_encode_compressed_default_values(self) -> None:
        cert = Certificate(
            serial_number=bytes.fromhex("01"),
            signature=bytes.fromhex(
                (
                    "00304402201610f6e9fbc7ddfd46bb9b585627285daf676eb3a950d99ed6d46276"
                    "3ef5fb7102202208fd466e06a77327865c50430e73f808389644351b390b92eee8"
                    "53eacb2600"
                )
            ),
            issuer=bytes.fromhex("697373756572"),
            validity_not_before=bytes.fromhex("3230303130313030303030305A"),
            validity_not_after=bytes.fromhex("3439303130313030303030305A"),
            subject=bytes.fromhex("7375626a656374"),
            key_info_subject_public_key=bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )
        result = cert.encode_compressed()

        self.assertEqual(
            result,
            bytes.fromhex(
                (
                    "3081940402000030818d85420004842242f6182ba1c1138d32b77fb9f7f3"
                    "7b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4"
                    "f4e5a59251d45243ac8544a665cb951422f864700304402201610f6e9fbc7"
                    "ddfd46bb9b585627285daf676eb3a950d99ed6d462763ef5fb7102202208f"
                    "d466e06a77327865c50430e73f808389644351b390b92eee853eacb2600"
                )
            ),
        )

    def test_decode_compressed_reference(self) -> None:
        encoded = bytes.fromhex(
            (
                "3081950402000030818e85420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f"
                "04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8"
                "544a665cb951422f86480030450221008720a2f08626d56b7814b7e5bbe04381e1834c"
                "f9a2a5d4c85c76783607a22cc60220236a4b757cd497c8570e84fa3221be99f6c78cc7"
                "cbc71d7328aa99be03f1eccf"
            )
        )

        certificate = Certificate.decode_compressed(encoded)

        self.assertEqual(certificate.serial_number, bytes.fromhex("01"))
        self.assertEqual(certificate.issuer, bytes.fromhex("697373756572"))
        self.assertEqual(
            certificate.validity_not_before, bytes.fromhex("3230303130313030303030305a")
        )
        self.assertEqual(
            certificate.validity_not_after, bytes.fromhex("3439303130313030303030305a")
        )
        self.assertEqual(certificate.subject, bytes.fromhex("7375626a656374"))
        self.assertEqual(
            certificate.key_info_subject_public_key,
            bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )
        self.assertEqual(
            certificate.signature,
            bytes.fromhex(
                (
                    "0030450221008720a2f08626d56b7814b7e5bbe04381e1834cf9a2a5d4c85c7678"
                    "3607a22cc60220236a4b757cd497c8570e84fa3221be99f6c78cc7cbc71d7328aa"
                    "99be03f1eccf"
                )
            ),
        )

    def test_decode_compressed_customized_fields(self) -> None:
        cert = Certificate.decode_compressed(
            bytes.fromhex(
                (
                    "30819f040200003081988000810082008300840085420004842242f6182ba1c113"
                    "8d32b77fb9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acf"
                    "c3401c3a4f4e5a59251d45243ac8544a665cb951422f8648003045022100e1ad64"
                    "0dceb11eac0292ce94cf668e074e2ca4a007a84424aa05aac4a1f623ad02205541"
                    "fe105df6b7d618976e7369bbbecd297275402d1ce37f729970b873ef1000"
                )
            )
        )
        self.assertEqual(
            cert.key_info_subject_public_key,
            bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )
        self.assertEqual(
            cert.signature,
            bytes.fromhex(
                (
                    "003045022100e1ad640dceb11eac0292ce94cf668e074e2ca4a007a84424aa05aa"
                    "c4a1f623ad02205541fe105df6b7d618976e7369bbbecd297275402d1ce37f7299"
                    "70b873ef1000"
                )
            ),
        )

    def test_decode_compressed_error(self) -> None:
        encoded = bytes.fromhex(
            (
                "3081c0040200003081b9800604278ba9fd718112637573746f6d20697373756572206e"
                "616d65830d3235303530353030303030305a85420004842242f6182ba1c1138d32b77f"
                "b9f7f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e"
                "5a59251d45243ac8544a665cb951422f8648003045022100e1ad640dceb11eac0292ce"
                "94cf668e074e2ca4a007a84424aa05aac4a1f623ad02205541fe105df6b7d618976e73"
                "69bbbecd297275402d1ce37f729970b873ef00"
            )
        )

        with self.assertRaises(CertificateDecodingError):
            Certificate.decode_compressed(encoded)

    def test_decode_compressed_default_values(self) -> None:
        encoded = bytes.fromhex(
            (
                "3081940402000030818d85420004842242f6182ba1c1138d32b77fb9f7f3"
                "7b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4"
                "f4e5a59251d45243ac8544a665cb951422f864700304402201610f6e9fbc7"
                "ddfd46bb9b585627285daf676eb3a950d99ed6d462763ef5fb7102202208f"
                "d466e06a77327865c50430e73f808389644351b390b92eee853eacb2600"
            )
        )
        certificate = Certificate.decode_compressed(encoded)

        self.assertEqual(certificate.serial_number, bytes.fromhex("01"))
        self.assertEqual(certificate.issuer, bytes.fromhex("697373756572"))
        self.assertEqual(
            certificate.validity_not_before, bytes.fromhex("3230303130313030303030305A")
        )
        self.assertEqual(
            certificate.validity_not_after, bytes.fromhex("3439303130313030303030305A")
        )
        self.assertEqual(certificate.subject, bytes.fromhex("7375626a656374"))
        self.assertEqual(
            certificate.key_info_subject_public_key,
            bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
        )
        self.assertEqual(
            certificate.signature,
            bytes.fromhex(
                (
                    "00304402201610f6e9fbc7ddfd46bb9b585627285daf676eb3a950d99ed6d46276"
                    "3ef5fb7102202208fd466e06a77327865c50430e73f808389644351b390b92eee8"
                    "53eacb2600"
                )
            ),
        )

    def test_generate(self) -> None:
        cert_issuer = KeyPair(
            private_key=bytes.fromhex(
                "308187020100301306072a8648ce3d020106082a8648ce3d"
                "030107046d306b02010104204b45df37a327a31303113f9965d14de94f025f881515e1"
                "3034a3d8a9ac47e43ea14403420004793e3a8f20428d54e7318046d75d05a8737eb6e0"
                "74e5146a207bff62dae90e24039f372814a312c3cb82a5a97bb5bfa9e623a3cc886b09"
                "dc13d53ef0da7de7bd"
            )
        )

        out = Certificate.generate(
            serial_number=bytes.fromhex("01"),
            issuer=bytes.fromhex("697373756572"),
            validity_not_before=bytes.fromhex("3230303130313030303030305A"),
            validity_not_after=bytes.fromhex("3439303130313030303030305A"),
            subject=bytes.fromhex("7375626a656374"),
            key_info_subject_public_key=bytes.fromhex(
                (
                    "0004842242f6182ba1c1138d32b77fb9f7f37b70034b9f04443a5bea3c188beadb"
                    "36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665cb951422f"
                )
            ),
            issuer_keypair=cert_issuer,
        )

        reference = bytes.fromhex(
            (
                "308201523081f9a003020102020101300a06082a8648ce3d0403023011310f300d0603"
                "5504030c06697373756572301e170d3230303130313030303030305a170d3439303130"
                "313030303030305a30123110300e06035504030c077375626a6563743059301306072a"
                "8648ce3d020106082a8648ce3d03010703420004842242f6182ba1c1138d32b77fb9f7"
                "f37b70034b9f04443a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59"
                "251d45243ac8544a665cb951422fa341303f301f0603551d230418301680142318e556"
                "71f08eae212142a817720fb817ee93bf300c0603551d130101ff04023000300e060355"
                "1d0f0101ff040403020780300a06082a8648ce3d04030203480030450221008720a2f0"
                "8626d56b7814b7e5bbe04381e1834cf9a2a5d4c85c76783607a22cc60220236a4b757c"
                "d497c8570e84fa3221be99f6c78cc7cbc71d7328aa99be03f1eccf"
            )
        )

        # Check that the certificate data matches
        cert_out = x509.load_der_x509_certificate(out)
        cert_ref = x509.load_der_x509_certificate(reference)
        self.assertEqual(cert_out.tbs_certificate_bytes, cert_ref.tbs_certificate_bytes)

        # Check signature by validating cert
        cert = Certificate.decode(out)
        self.assertTrue(cert.verify(cert_issuer.get_public_key()))

    def test_verify_decompressed(self) -> None:
        certificate = bytes.fromhex(
            "308201523081f9a003020102020101300a06082a8648ce3d0403023011310f300d06035504"
            "030c06697373756572301e170d3230303130313030303030305a170d343930313031303030"
            "3030305a30123110300e06035504030c077375626a6563743059301306072a8648ce3d0201"
            "06082a8648ce3d03010703420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f0444"
            "3a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665c"
            "b951422fa341303f301f0603551d230418301680142318e55671f08eae212142a817720fb8"
            "17ee93bf300c0603551d130101ff04023000300e0603551d0f0101ff040403020780300a06"
            "082a8648ce3d04030203480030450221008720a2f08626d56b7814b7e5bbe04381e1834cf9"
            "a2a5d4c85c76783607a22cc60220236a4b757cd497c8570e84fa3221be99f6c78cc7cbc71d"
            "7328aa99be03f1eccf"
        )

        issuer_key = PublicKey(
            bytes.fromhex(
                "04793e3a8f20428d54e7318046d75d05a8737eb6e074e5146a207bff62dae90e24039f"
                "372814a312c3cb82a5a97bb5bfa9e623a3cc886b09dc13d53ef0da7de7bd"
            )
        )

        cert = Certificate.decode(certificate)
        self.assertTrue(cert.verify(issuer_key))

    def test_verify_compressed(self) -> None:
        certificate = bytes.fromhex(
            "3081950402000030818e85420004842242f6182ba1c1138d32b77fb9f7f37b70034b9f0444"
            "3a5bea3c188beadb36490a7e95f91a4c162acfc3401c3a4f4e5a59251d45243ac8544a665c"
            "b951422f86480030450221008720a2f08626d56b7814b7e5bbe04381e1834cf9a2a5d4c85c"
            "76783607a22cc60220236a4b757cd497c8570e84fa3221be99f6c78cc7cbc71d7328aa99be"
            "03f1eccf"
        )

        issuer_key = PublicKey(
            bytes.fromhex(
                "04793e3a8f20428d54e7318046d75d05a8737eb6e074e5146a207bff62dae90e24039f"
                "372814a312c3cb82a5a97bb5bfa9e623a3cc886b09dc13d53ef0da7de7bd"
            )
        )

        cert = Certificate.decode_compressed(certificate)
        self.assertTrue(cert.verify(issuer_key))
