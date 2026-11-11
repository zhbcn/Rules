import socket
import struct
import unittest

from scripts.probe_ai_direct import classification, decode_a


class DirectProbeTest(unittest.TestCase):
    def response(self, ip, ident=42, flags=0x8180):
        question = b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(ip)
        return struct.pack('!6H', ident, flags, 1, 1, 0, 0) + question + answer

    def test_compressed_dns_name_and_public_address(self):
        self.assertEqual(decode_a(self.response('8.8.8.8'), 42), ['8.8.8.8'])

    def test_rejects_local_fake_and_private_answers(self):
        for ip in ['127.0.0.1', '10.0.0.1', '192.168.1.1', '198.18.0.1', '198.19.1.1']:
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                decode_a(self.response(ip), 42)

    def test_rejects_wrong_id_failed_or_truncated_dns(self):
        for data in [self.response('8.8.8.8', ident=41), self.response('8.8.8.8', flags=0x8183), self.response('8.8.8.8', flags=0x8380), b'bad']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode_a(data, 42)

    def test_auth_and_not_found_do_not_claim_application_success(self):
        self.assertEqual(classification(401, '{}'), 'authentication_required_only')
        self.assertEqual(classification(404, ''), 'server_reachable_path_not_validated')
        self.assertEqual(classification(403, ''), 'forbidden_not_validated')

    def test_region_message_overrides_successful_http_status(self):
        self.assertEqual(classification(200, 'Not available in your country'), 'restricted_or_challenged')
        self.assertEqual(classification(200, 'cf-chl-token'), 'restricted_or_challenged')
        self.assertEqual(classification(206, 'binary download'), 'public_entry_reachable')


if __name__ == '__main__':
    unittest.main()
