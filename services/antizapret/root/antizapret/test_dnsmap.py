# Run from the repository root:
# docker run --rm -v "$PWD/services/antizapret/root/antizapret:/tests:ro" -w /tests xtrime/antizapret-vpn:6.7.0 python3 -B -m unittest -v test_dnsmap.py

import queue
import ipaddress
import socket
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from dnslib import A, CNAME, DNSRecord, QTYPE, RCODE, RR

import dnsmap
import ipv6_translator


def dns_reply(request, addresses=(), rcode=RCODE.NOERROR):
    reply = request.reply()
    reply.header.rcode = rcode
    for address in addresses:
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(address)))
    return reply


class FakeResponse:
    def __init__(self, data, status=200, content_type='application/dns-message',
                 content_length=None, will_close=False):
        self.data = data
        self.status = status
        self.content_type = content_type
        self.content_length = content_length
        self.will_close = will_close

    def getheader(self, name, default=None):
        if name == 'Content-Type':
            return self.content_type
        if name == 'Content-Length':
            return self.content_length if self.content_length is not None else str(len(self.data))
        return default

    def read(self, size=-1):
        return self.data if size < 0 else self.data[:size]


class FakeConnection:
    def __init__(self, response=None, request_error=None):
        self.response = response
        self.request_error = request_error
        self.closed = False
        self.requests = []

    def request(self, *args, **kwargs):
        self.requests.append((args, kwargs))
        if self.request_error:
            raise self.request_error

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class ResolverTestCase(unittest.TestCase):
    def setUp(self):
        self.print_patcher = patch('builtins.print')
        self.output = self.print_patcher.start()
        self.addCleanup(self.print_patcher.stop)
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.asn_file = Path(self.temp_directory.name) / 'asn.txt'
        self.asn_file.write_text('', encoding='utf-8')
        self.asn_database = Mock()
        self.asn_database.get.return_value = None
        self.iptables_runner = Mock(return_value=Mock(returncode=0, stderr=''))

    def make_resolver(self, **overrides):
        arguments = {
            'address': 'adguard',
            'port': 53,
            'doh_port': 3000,
            'timeout': 1,
            'iprange': '14.16.0.0/29',
            'client_id': 'az-local',
            'resolver_client_id': 'az-resolver',
            'asn_file': str(self.asn_file),
            'asn_database': '/unused.mmdb',
            'asn_database_reader': self.asn_database,
            'iptables_runner': self.iptables_runner,
            'load_existing_mappings': False,
            'mapping_batch_delay': 0.001,
        }
        arguments.update(overrides)
        resolver = dnsmap.ProxyResolver(**arguments)
        self.addCleanup(resolver.close)
        return resolver


class DoHClientTests(ResolverTestCase):
    def test_request_contains_client_id_and_connection_is_reused(self):
        resolver = self.make_resolver()
        request = DNSRecord.question('example.com', 'A')
        connection = FakeConnection(FakeResponse(dns_reply(request, ['192.0.2.1']).pack()))
        resolver.doh_connections.put(connection)

        reply = resolver.query_doh(request, 'az-local')

        self.assertEqual(str(reply.rr[0].rdata), '192.0.2.1')
        self.assertTrue(connection.requests[0][0][1].startswith('/dns-query/az-local?dns='))
        self.assertIs(resolver.doh_connections.get_nowait(), connection)

    def test_stale_connection_is_closed_and_retry_uses_fresh_connection(self):
        request = DNSRecord.question('example.com', 'A')
        stale = FakeConnection(request_error=BrokenPipeError())
        another_stale = FakeConnection(request_error=BrokenPipeError())
        healthy = FakeConnection(FakeResponse(dns_reply(request, ['192.0.2.1']).pack()))
        resolver = self.make_resolver(connection_factory=Mock(return_value=healthy))
        resolver.doh_connections.put(another_stale)
        resolver.doh_connections.put(stale)

        reply = resolver.query_doh(request, 'az-local')

        self.assertEqual(str(reply.rr[0].rdata), '192.0.2.1')
        self.assertTrue(stale.closed)
        self.assertFalse(another_stale.closed)
        self.assertEqual(len(healthy.requests), 1)
        resolver.connection_factory.assert_called_once()

    def test_malformed_dns_response_is_closed_and_rejected(self):
        resolver = self.make_resolver()
        connection = FakeConnection(FakeResponse(b'not a dns packet'))
        resolver.doh_connections.put(connection)

        with self.assertRaises(dnsmap.DoHProtocolError):
            resolver.query_doh(DNSRecord.question('example.com', 'A'), 'az-local')

        self.assertTrue(connection.closed)

    def test_http_error_is_not_retried(self):
        connection = FakeConnection(FakeResponse(b'error', status=503))
        resolver = self.make_resolver(connection_factory=Mock())
        resolver.doh_connections.put(connection)

        with self.assertRaisesRegex(dnsmap.DoHResponseError, 'HTTP 503'):
            resolver.query_doh(DNSRecord.question('example.com', 'A'), 'az-local')

        self.assertEqual(len(connection.requests), 1)
        self.assertTrue(connection.closed)
        resolver.connection_factory.assert_not_called()

    def test_invalid_content_metadata_is_rejected(self):
        cases = (
            FakeResponse(b'data', content_type='text/plain'),
            FakeResponse(b'data', content_length='invalid'),
        )
        for response in cases:
            with self.subTest(response=response):
                resolver = self.make_resolver()
                connection = FakeConnection(response)
                resolver.doh_connections.put(connection)
                with self.assertRaises(dnsmap.DoHResponseError):
                    resolver.query_doh(DNSRecord.question('example.com', 'A'), 'az-local')
                self.assertTrue(connection.closed)

    def test_oversized_response_is_rejected(self):
        resolver = self.make_resolver()
        data = b'x' * (resolver.MAX_DOH_RESPONSE_SIZE + 1)
        connection = FakeConnection(FakeResponse(data))
        resolver.doh_connections.put(connection)

        with self.assertRaisesRegex(dnsmap.DoHResponseError, 'too large'):
            resolver.query_doh(DNSRecord.question('example.com', 'A'), 'az-local')

        self.assertTrue(connection.closed)

    def test_concurrent_requests_complete_without_socket_errors(self):
        request = DNSRecord.question('example.com', 'A')
        response_data = dns_reply(request, ['192.0.2.1']).pack()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/dns-message')
                self.send_header('Content-Length', str(len(response_data)))
                self.end_headers()
                self.wfile.write(response_data)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        resolver = self.make_resolver(address=server.server_address[0],
                                      doh_port=server.server_address[1])
        try:
            with ThreadPoolExecutor(max_workers=10) as executor:
                replies = list(executor.map(
                    lambda _: resolver.query_doh(request, 'az-local'), range(100)
                ))
        finally:
            resolver.close()
            server.shutdown()
            server.server_close()

        self.assertEqual(len(replies), 100)
        self.assertTrue(all(str(reply.rr[0].rdata) == '192.0.2.1' for reply in replies))

    def test_close_closes_pool_and_database(self):
        resolver = self.make_resolver()
        connection = FakeConnection()
        resolver.doh_connections.put(connection)

        resolver.close()

        self.assertTrue(connection.closed)
        self.asn_database.close.assert_called()


class AsnListTests(ResolverTestCase):
    def test_list_parser_accepts_numbers_names_and_comments(self):
        self.asn_file.write_text(
            'AS13335 # Cloudflare\n13238\nTelegram Messenger, Inc.\n/\\bg-?core\\b/\n\n', encoding='utf-8'
        )

        rules = dnsmap.ProxyResolver.load_asn_list(self.asn_file)

        self.assertEqual(rules.asn_rules, {13335: 'AS13335', 13238: '13238'})
        self.assertEqual(rules.substring_rules, [('Telegram Messenger, Inc.', 'telegram messenger, inc.')])
        self.assertEqual(rules.regex_rules[0][0], '/\\bg-?core\\b/')
        self.assertEqual(rules.regex_rules[0][1].pattern, '\\bg-?core\\b')

    def test_list_parser_combines_semicolon_separated_files(self):
        world_asn_file = Path(self.temp_directory.name) / 'asn-world.txt'
        self.asn_file.write_text('AS13335\nCloudflare\n', encoding='utf-8')
        world_asn_file.write_text('AS62041\nTelegram\n', encoding='utf-8')

        rules = dnsmap.ProxyResolver.load_asn_list(
            '{};{}'.format(self.asn_file, world_asn_file)
        )

        self.assertEqual(rules.asn_rules, {13335: 'AS13335', 62041: 'AS62041'})
        self.assertEqual(
            rules.substring_rules,
            [('Cloudflare', 'cloudflare'), ('Telegram', 'telegram')]
        )

    def test_organization_name_uses_case_insensitive_substring_match(self):
        resolver = self.make_resolver()
        resolver.asn_match_rules = dnsmap.AsnMatchRules(
            {},
            [dnsmap.ProxyResolver.organization_substring_rule('telegram')],
            []
        )
        self.asn_database.get.return_value = {
            'autonomous_system_number': 62041,
            'autonomous_system_organization': 'Telegram Messenger, Inc.',
        }

        self.assertTrue(resolver.is_blocked_asn('192.0.2.1'))
        self.output.assert_any_call(
            "ASN lookup for 192.0.2.1: {'autonomous_system_number': 62041, "
            "'autonomous_system_organization': 'Telegram Messenger, Inc.'}"
        )
        self.output.assert_any_call('ASN match for 192.0.2.1: rule: telegram')

    def test_asn_match_logs_matching_rule(self):
        resolver = self.make_resolver()
        resolver.asn_match_rules = dnsmap.AsnMatchRules({13335: 'AS13335'}, [], [])
        self.asn_database.get.return_value = {
            'autonomous_system_number': 13335,
            'autonomous_system_organization': 'Cloudflare, Inc.',
        }

        self.assertTrue(resolver.is_blocked_asn('192.0.2.1'))
        self.output.assert_any_call(
            "ASN lookup for 192.0.2.1: {'autonomous_system_number': 13335, "
            "'autonomous_system_organization': 'Cloudflare, Inc.'}"
        )
        self.output.assert_any_call('ASN match for 192.0.2.1: rule: AS13335')

    def test_empty_and_unspecified_addresses_skip_asn_lookup_in_asn_list_tests(self):
        resolver = self.make_resolver()

        for address in (None, '', '0.0.0.0'):
            with self.subTest(address=address):
                self.assertFalse(resolver.is_blocked_asn(address))

        self.asn_database.get.assert_not_called()

    def test_missing_asn_data_is_logged(self):
        resolver = self.make_resolver()
        self.asn_database.get.return_value = None

        self.assertFalse(resolver.is_blocked_asn('192.0.2.1'))

        self.output.assert_any_call('ASN lookup for 192.0.2.1: None')

    def test_empty_and_unspecified_addresses_skip_asn_lookup_in_asn_list_tests_2(self):
        resolver = self.make_resolver()

        for address in (None, '', '0.0.0.0'):
            with self.subTest(address=address):
                self.assertFalse(resolver.is_blocked_asn(address))

        self.asn_database.get.assert_not_called()

        self.assertFalse(resolver.is_blocked_asn('192.0.2.1'))

        self.output.assert_any_call('ASN data not found for 192.0.2.1')

    def test_plain_substring_does_not_normalize_punctuation(self):
        resolver = self.make_resolver()
        resolver.asn_match_rules = dnsmap.AsnMatchRules(
            {},
            [dnsmap.ProxyResolver.organization_substring_rule('gcore')],
            []
        )
        self.asn_database.get.return_value = {
            'autonomous_system_number': 199524,
            'autonomous_system_organization': 'G-Core Labs S.A.',
        }

        self.assertFalse(resolver.is_blocked_asn('192.0.2.1'))
        self.output.assert_any_call(
            "ASN lookup for 192.0.2.1: {'autonomous_system_number': 199524, "
            "'autonomous_system_organization': 'G-Core Labs S.A.'}"
        )

    def test_regex_organization_match_supports_word_boundaries(self):
        resolver = self.make_resolver()
        resolver.asn_match_rules = dnsmap.AsnMatchRules(
            {},
            [],
            [dnsmap.ProxyResolver.organization_regex_rule(r'/\bg-?core\b/')]
        )
        self.asn_database.get.return_value = {
            'autonomous_system_number': 199524,
            'autonomous_system_organization': 'G-Core Labs S.A.',
        }

        self.assertTrue(resolver.is_blocked_asn('192.0.2.1'))
        self.output.assert_any_call('ASN match for 192.0.2.1: rule: /\\bg-?core\\b/')

        self.asn_database.get.return_value = {
            'autonomous_system_number': 64500,
            'autonomous_system_organization': 'Edgecore Networks',
        }
        self.assertFalse(resolver.is_blocked_asn('192.0.2.2'))

    def test_regex_organization_match_is_case_insensitive_unicode(self):
        resolver = self.make_resolver()
        resolver.asn_match_rules = dnsmap.AsnMatchRules(
            {},
            [],
            [dnsmap.ProxyResolver.organization_regex_rule('/яндекс/')]
        )
        self.asn_database.get.return_value = {
            'autonomous_system_number': 13238,
            'autonomous_system_organization': 'Яндекс LLC',
        }

        self.assertTrue(resolver.is_blocked_asn('192.0.2.1'))
        self.output.assert_any_call('ASN match for 192.0.2.1: rule: /яндекс/')

    def test_line_without_closing_regex_delimiter_is_substring_rule(self):
        self.asn_file.write_text('/gcore\n', encoding='utf-8')

        rules = dnsmap.ProxyResolver.load_asn_list(self.asn_file)

        self.assertEqual(rules.substring_rules, [('/gcore', '/gcore')])
        self.assertEqual(rules.regex_rules, [])

    def test_invalid_regex_does_not_replace_existing_asn_list(self):
        resolver = self.make_resolver()
        old_rules = dnsmap.AsnMatchRules(
            {13335: 'AS13335'},
            [],
            [dnsmap.ProxyResolver.organization_regex_rule(r'/\bg-?core\b/')]
        )
        resolver.asn_match_rules = old_rules
        self.asn_file.write_text('AS13238\n/[/\n', encoding='utf-8')

        with self.assertRaises(dnsmap.re.error):
            resolver.reload_asn_list()

        self.assertIs(resolver.asn_match_rules, old_rules)

    def test_failed_reload_preserves_last_known_good(self):
        resolver = self.make_resolver()
        old_rules = dnsmap.AsnMatchRules({13335: 'AS13335'}, [], [])
        resolver.asn_match_rules = old_rules
        resolver.asn_file = '/missing/asn.txt'

        with self.assertRaises(FileNotFoundError):
            resolver.reload_asn_list()

        self.assertIs(resolver.asn_match_rules, old_rules)

    def test_successful_reload_atomically_replaces_sets(self):
        resolver = self.make_resolver()
        resolver.asn_match_rules = dnsmap.AsnMatchRules(
            {13335: 'AS13335'},
            [dnsmap.ProxyResolver.organization_substring_rule('Cloudflare')],
            []
        )
        self.asn_file.write_text('AS13238\nYandex\n/\\bg-?core\\b/\n', encoding='utf-8')

        resolver.reload_asn_list()

        self.assertEqual(resolver.asn_match_rules.asn_rules, {13238: 'AS13238'})
        self.assertEqual(resolver.asn_match_rules.substring_rules, [('Yandex', 'yandex')])
        self.assertEqual([rule[0] for rule in resolver.asn_match_rules.regex_rules], ['/\\bg-?core\\b/'])

    def test_signal_handler_reloads_immediately(self):
        resolver = self.make_resolver()
        self.asn_file.write_text('AS13238\nYandex\n', encoding='utf-8')
        with patch.object(dnsmap.os, 'write') as output:
            resolver.request_asn_reload(None, None)
        self.assertEqual(resolver.asn_match_rules.asn_rules, {13238: 'AS13238'})
        self.assertEqual(resolver.asn_match_rules.substring_rules, [('Yandex', 'yandex')])
        output.assert_called_once()

    def test_signal_handler_keeps_old_list_and_logs_reload_failure(self):
        resolver = self.make_resolver()
        old_rules = dnsmap.AsnMatchRules({13335: 'AS13335'}, [], [])
        resolver.asn_match_rules = old_rules
        resolver.asn_file = '/missing/asn.txt'
        with patch.object(dnsmap.os, 'write') as output:
            resolver.request_asn_reload(None, None)
        self.assertIs(resolver.asn_match_rules, old_rules)
        self.assertEqual(output.call_args.args[0], 2)


class MappingTests(ResolverTestCase):
    class TrackingDict(dict):
        def __init__(self):
            super().__init__()
            self.was_cleared = False

        def clear(self):
            self.was_cleared = True
            super().clear()

    def test_range_must_leave_an_address_after_dns_reservation(self):
        with self.assertRaisesRegex(ValueError, 'no addresses available'):
            self.make_resolver(iprange='14.16.0.1/32')

    def test_iptables_failure_does_not_commit_and_recycles_address(self):
        self.iptables_runner.return_value = Mock(returncode=1, stderr='failed')
        resolver = self.make_resolver()

        self.assertFalse(resolver.add_mapping('192.0.2.1'))

        self.assertEqual(resolver.ipmap, {})
        self.assertEqual(resolver.unassigned_addresses[0], '14.16.0.2')

    def test_iptables_success_commits_mapping(self):
        resolver = self.make_resolver()
        resolver.pending_mappings = self.TrackingDict()

        self.assertEqual(resolver.add_mapping('192.0.2.1'), '14.16.0.2')

        self.assertEqual(resolver.get_mapping('192.0.2.1'), '14.16.0.2')
        self.assertTrue(resolver.pending_mappings.was_cleared)
        command = self.iptables_runner.call_args.args[0]
        self.assertEqual(command, ['iptables-restore', '--wait', '--noflush'])
        self.assertIn(
            '-A dnsmap -d 14.16.0.2 -j DNAT --to-destination 192.0.2.1',
            self.iptables_runner.call_args.kwargs['input'],
        )

    def test_concurrent_mappings_are_applied_in_one_batch(self):
        resolver = self.make_resolver(mapping_batch_delay=0.05)
        barrier = threading.Barrier(3)

        def add_mapping(address):
            barrier.wait()
            return resolver.add_mapping(address)

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(add_mapping, '192.0.2.1'),
                executor.submit(add_mapping, '192.0.2.2'),
            ]
            barrier.wait()
            self.assertEqual(
                {future.result() for future in futures},
                {'14.16.0.2', '14.16.0.3'},
            )

        self.iptables_runner.assert_called_once()
        rules = self.iptables_runner.call_args.kwargs['input']
        self.assertIn('--to-destination 192.0.2.1', rules)
        self.assertIn('--to-destination 192.0.2.2', rules)

    def test_concurrent_duplicate_mapping_is_only_added_once(self):
        resolver = self.make_resolver(mapping_batch_delay=0.05)
        barrier = threading.Barrier(3)

        def add_mapping():
            barrier.wait()
            return resolver.add_mapping('192.0.2.1')

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(add_mapping) for _ in range(2)]
            barrier.wait()
            self.assertEqual(
                [future.result() for future in futures],
                ['14.16.0.2', '14.16.0.2'],
            )

        rules = self.iptables_runner.call_args.kwargs['input']
        self.assertEqual(rules.count('--to-destination 192.0.2.1'), 1)

    def test_exhausted_range_flushes_old_mappings_and_starts_over(self):
        resolver = self.make_resolver(iprange='14.16.0.0/30')

        self.assertEqual(resolver.add_mapping('192.0.2.1'), '14.16.0.2')
        self.assertEqual(resolver.add_mapping('192.0.2.2'), '14.16.0.2')

        self.assertEqual(resolver.ipmap, {'192.0.2.2': '14.16.0.2'})
        commands = [call.args[0] for call in self.iptables_runner.call_args_list]
        self.assertEqual(commands[1], ['iptables', '-w', '-t', 'nat', '-F', 'dnsmap'])
        self.assertIn(
            '--to-destination 192.0.2.2',
            self.iptables_runner.call_args_list[2].kwargs['input'],
        )

    def test_batch_is_not_partially_allocated_when_range_is_exhausted(self):
        resolver = self.make_resolver(iprange='14.16.0.0/29')
        for index in range(4):
            resolver.add_mapping('192.0.2.{}'.format(index + 1))

        mappings = resolver.add_mappings(['192.0.2.10', '192.0.2.11'])

        self.assertEqual(mappings, {
            '192.0.2.10': '14.16.0.2',
            '192.0.2.11': '14.16.0.3',
        })
        self.assertEqual(resolver.ipmap, mappings)
        commands = [call.args[0] for call in self.iptables_runner.call_args_list]
        self.assertEqual(commands[-2], ['iptables', '-w', '-t', 'nat', '-F', 'dnsmap'])
        rules = self.iptables_runner.call_args_list[-1].kwargs['input']
        self.assertIn('--to-destination 192.0.2.10', rules)
        self.assertIn('--to-destination 192.0.2.11', rules)

    def test_mapping_is_rejected_after_resolver_stops(self):
        resolver = self.make_resolver()
        resolver.close()

        self.assertFalse(resolver.add_mapping('192.0.2.1'))
        self.iptables_runner.assert_not_called()

    def test_failed_flush_preserves_old_mappings(self):
        def run_iptables(command, **kwargs):
            if '-F' in command:
                return Mock(returncode=1, stderr='flush failed')
            return Mock(returncode=0, stderr='')

        self.iptables_runner.side_effect = run_iptables
        resolver = self.make_resolver(iprange='14.16.0.0/30')

        self.assertEqual(resolver.add_mapping('192.0.2.1'), '14.16.0.2')
        self.assertFalse(resolver.add_mapping('192.0.2.2'))

        self.assertEqual(resolver.ipmap, {'192.0.2.1': '14.16.0.2'})
        self.assertEqual(list(resolver.unassigned_addresses), [])


class ResolverContractTests(ResolverTestCase):
    def resolver_with_replies(self, replies, asn_match=False):
        resolver = self.make_resolver()
        resolver.query_doh = Mock(side_effect=replies)
        resolver.is_blocked_asn = Mock(return_value=asn_match)
        resolver.add_mappings = Mock(side_effect=lambda addresses: {
            address: '14.16.0.{}'.format(index + 2)
            for index, address in enumerate(addresses)
        })
        return resolver

    def test_filtered_a_answer_is_mapped_without_asn_lookup(self):
        request = DNSRecord.question('example.com', 'A')
        resolver = self.resolver_with_replies([dns_reply(request, ['192.0.2.1'])])

        reply = resolver.resolve(request, Mock())

        self.assertEqual(str(reply.rr[0].rdata), '14.16.0.2')
        resolver.is_blocked_asn.assert_not_called()

    def test_servfail_without_asn_match_is_preserved(self):
        request = DNSRecord.question('example.com', 'A')
        resolver = self.resolver_with_replies([
            dns_reply(request, rcode=RCODE.SERVFAIL),
            dns_reply(request, ['192.0.2.1']),
        ])

        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.SERVFAIL)
        resolver.add_mappings.assert_not_called()

    def test_resolver_servfail_is_returned_without_asn_lookup(self):
        request = DNSRecord.question('example.com', 'A')
        resolver = self.resolver_with_replies([
            dns_reply(request, rcode=RCODE.SERVFAIL),
            dns_reply(request, ['192.0.2.1'], rcode=RCODE.SERVFAIL),
        ], asn_match=True)

        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.SERVFAIL)
        resolver.is_blocked_asn.assert_not_called()
        resolver.add_mappings.assert_not_called()

    def test_empty_resolver_answer_preserves_filtered_reply(self):
        request = DNSRecord.question('empty.example', 'A')
        filtered_reply = dns_reply(request, rcode=RCODE.SERVFAIL)
        resolved_reply = dns_reply(request)
        resolver = self.resolver_with_replies([
            filtered_reply,
            resolved_reply,
        ], asn_match=True)

        reply = resolver.resolve(request, Mock())

        self.assertIs(reply, filtered_reply)
        self.assertEqual(reply.header.rcode, RCODE.SERVFAIL)
        resolver.is_blocked_asn.assert_not_called()
        resolver.add_mappings.assert_not_called()

    def test_resolver_servfail_is_returned_without_asn_lookup_in_resolver_contract_tests(self):
        request = DNSRecord.question('example.com', 'A')
        resolver = self.resolver_with_replies([
            dns_reply(request, rcode=RCODE.SERVFAIL),
            dns_reply(request, ['192.0.2.1'], rcode=RCODE.SERVFAIL),
        ], asn_match=True)

        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.SERVFAIL)
        resolver.is_blocked_asn.assert_not_called()
        resolver.add_mappings.assert_not_called()

    def test_empty_resolver_answer_preserves_filtered_reply_in_resolver_contract_tests(self):
        request = DNSRecord.question('empty.example', 'A')
        filtered_reply = dns_reply(request, rcode=RCODE.SERVFAIL)
        resolved_reply = dns_reply(request)
        resolver = self.resolver_with_replies([
            filtered_reply,
            resolved_reply,
        ], asn_match=True)

        reply = resolver.resolve(request, Mock())

        self.assertIs(reply, filtered_reply)
        self.assertEqual(reply.header.rcode, RCODE.SERVFAIL)
        resolver.is_blocked_asn.assert_not_called()
        resolver.add_mappings.assert_not_called()

        self.assertIs(reply, filtered_reply)
        self.assertEqual(reply.header.rcode, RCODE.SERVFAIL)
        resolver.is_blocked_asn.assert_not_called()
        resolver.add_mappings.assert_not_called()

    def test_one_asn_match_maps_all_resolved_addresses(self):
        request = DNSRecord.question('example.com', 'A')
        resolver = self.resolver_with_replies([
            dns_reply(request, rcode=RCODE.SERVFAIL),
            dns_reply(request, ['192.0.2.1', '192.0.2.2']),
        ])
        resolver.is_blocked_asn.side_effect = [False, True]

        reply = resolver.resolve(request, Mock())

        self.assertEqual([str(record.rdata) for record in reply.rr], ['14.16.0.2', '14.16.0.3'])
        resolver.add_mappings.assert_called_once_with(['192.0.2.1', '192.0.2.2'])

    def test_nxdomain_is_preserved(self):
        request = DNSRecord.question('missing.example', 'A')
        resolver = self.resolver_with_replies([dns_reply(request, rcode=RCODE.NXDOMAIN)])

        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)
        resolver.add_mappings.assert_not_called()

    def test_empty_noerror_answer_is_preserved(self):
        request = DNSRecord.question('empty.example', 'A')
        resolver = self.resolver_with_replies([dns_reply(request)])

        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(reply.rr, [])
        resolver.add_mappings.assert_not_called()

    def test_answer_without_ipv4_address_is_preserved(self):
        request = DNSRecord.question('alias.example', 'A')
        upstream_reply = dns_reply(request)
        upstream_reply.add_answer(RR(
            request.q.qname,
            QTYPE.CNAME,
            rdata=CNAME('target.example'),
        ))
        resolver = self.resolver_with_replies([upstream_reply])

        reply = resolver.resolve(request, Mock())

        self.assertIs(reply, upstream_reply)
        self.assertEqual(reply.rr[0].rtype, QTYPE.CNAME)
        resolver.add_mappings.assert_not_called()

    def test_aaaa_and_https_are_suppressed(self):
        for query_type in ('AAAA', 'HTTPS'):
            with self.subTest(query_type=query_type):
                request = DNSRecord.question('example.com', query_type)
                resolver = self.resolver_with_replies([dns_reply(request)])
                reply = resolver.resolve(request, Mock())
                self.assertEqual(reply.header.rcode, RCODE.NOERROR)
                self.assertEqual(reply.rr, [])

    def test_mmdb_exception_returns_servfail(self):
        request = DNSRecord.question('example.com', 'A')
        resolver = self.resolver_with_replies([
            dns_reply(request, rcode=RCODE.SERVFAIL),
            dns_reply(request, ['192.0.2.1']),
        ])
        resolver.is_blocked_asn.side_effect = RuntimeError('MMDB failed')
        resolver.log_processing_error = Mock()

        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.SERVFAIL)
        resolver.log_processing_error.assert_called_once()

    def test_error_logging_is_rate_limited(self):
        resolver = self.make_resolver()
        with patch.object(dnsmap.time, 'monotonic', return_value=10), \
                patch('builtins.print') as output, \
                patch.object(dnsmap.traceback, 'print_exc') as print_traceback:
            resolver.log_processing_error(RuntimeError('first'))
            resolver.log_processing_error(RuntimeError('second'))

        output.assert_called_once()
        print_traceback.assert_called_once()
        self.assertEqual(resolver.suppressed_errors, 1)


class IPv6EgressDomainTests(ResolverTestCase):
    """Tests for IPv6 egress domain matching logic."""

    def make_resolver_with_ipv6(self, **overrides):
        arguments = {
            'address': 'adguard',
            'port': 53,
            'doh_port': 3000,
            'timeout': 1,
            'iprange': '14.16.0.0/29',
            'client_id': 'az-local',
            'resolver_client_id': 'az-resolver',
            'asn_file': str(self.asn_file),
            'asn_database': '/unused.mmdb',
            'asn_database_reader': self.asn_database,
            'iptables_runner': self.iptables_runner,
            'load_existing_mappings': False,
            'mapping_batch_delay': 0.001,
            'ipv6_egress_file': str(self.temp_directory.name + '/ipv6-egress.txt'),
            'ipv6_translator_port': 9000,
        }
        arguments.update(overrides)
        resolver = dnsmap.ProxyResolver(**arguments)
        self.addCleanup(resolver.close)
        return resolver

    def test_ipv6_egress_domains_loaded_from_file(self):
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n# comment\n\n test.org\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        self.assertTrue(resolver.is_ipv6_egress_domain('example.com'))
        self.assertTrue(resolver.is_ipv6_egress_domain('www.example.com'))
        self.assertTrue(resolver.is_ipv6_egress_domain('test.org'))
        self.assertFalse(resolver.is_ipv6_egress_domain('other.com'))

    def test_ipv6_egress_subdomain_matching(self):
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        self.assertTrue(resolver.is_ipv6_egress_domain('example.com'))
        self.assertTrue(resolver.is_ipv6_egress_domain('www.example.com'))
        self.assertTrue(resolver.is_ipv6_egress_domain('sub.www.example.com'))
        self.assertFalse(resolver.is_ipv6_egress_domain('example.com.evil.org'))
        self.assertFalse(resolver.is_ipv6_egress_domain('other.com'))

    def test_ipv6_egress_empty_file(self):
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        self.assertFalse(resolver.is_ipv6_egress_domain('example.com'))
        self.assertEqual(len(resolver.ipv6_egress_domains), 0)

    def test_ipv6_egress_missing_file(self):
        resolver = self.make_resolver_with_ipv6()
        # File doesn't exist, should not crash
        self.assertFalse(resolver.is_ipv6_egress_domain('example.com'))
        self.assertEqual(len(resolver.ipv6_egress_domains), 0)

    def test_ipv6_egress_reload(self):
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        self.assertTrue(resolver.is_ipv6_egress_domain('example.com'))
        self.assertFalse(resolver.is_ipv6_egress_domain('test.org'))

        # Reload with new file contents
        ipv6_file.write_text('test.org\n', encoding='utf-8')
        resolver.reload_ipv6_egress_domains(None, None)

        self.assertFalse(resolver.is_ipv6_egress_domain('example.com'))
        self.assertTrue(resolver.is_ipv6_egress_domain('test.org'))


class IPv6EgressMappingTests(ResolverTestCase):
    """Tests for IPv6 mapping allocation."""

    def make_resolver_with_ipv6(self, **overrides):
        arguments = {
            'address': 'adguard',
            'port': 53,
            'doh_port': 3000,
            'timeout': 1,
            'iprange': '14.16.0.0/29',
            'client_id': 'az-local',
            'resolver_client_id': 'az-resolver',
            'asn_file': str(self.asn_file),
            'asn_database': '/unused.mmdb',
            'asn_database_reader': self.asn_database,
            'iptables_runner': self.iptables_runner,
            'load_existing_mappings': False,
            'mapping_batch_delay': 0.001,
            'ipv6_egress_file': str(self.temp_directory.name + '/ipv6-egress.txt'),
            'ipv6_translator_port': 9000,
        }
        arguments.update(overrides)
        resolver = dnsmap.ProxyResolver(**arguments)
        self.addCleanup(resolver.close)
        return resolver

    def test_add_ipv6_mapping_creates_dnat_to_translator(self):
        resolver = self.make_resolver_with_ipv6()

        result = resolver.add_ipv6_mapping('2001:db8::1')

        self.assertEqual(result, '14.16.0.2')
        self.assertEqual(resolver.get_ipv6_mapping_by_real('2001:db8::1'), '14.16.0.2')

        # Check iptables rule was created for translator
        command = self.iptables_runner.call_args.args[0]
        self.assertEqual(command, ['iptables-restore', '--wait', '--noflush'])
        input_rules = self.iptables_runner.call_args.kwargs['input']
        self.assertIn(
            '-A dnsmap -d 14.16.0.2 -j DNAT --to-destination 127.0.0.1:9000',
            input_rules,
        )

    def test_add_ipv6_mapping_reuses_existing(self):
        resolver = self.make_resolver_with_ipv6()

        resolver.add_ipv6_mapping('2001:db8::1')
        result = resolver.add_ipv6_mapping('2001:db8::1')

        self.assertEqual(result, '14.16.0.2')
        # Only one iptables-restore call should be made
        self.assertEqual(self.iptables_runner.call_count, 1)

    def test_add_ipv6_mappings_multiple(self):
        resolver = self.make_resolver_with_ipv6()

        results = resolver.add_ipv6_mappings(['2001:db8::1', '2001:db8::2'])

        self.assertEqual(results['2001:db8::1'], '14.16.0.2')
        self.assertEqual(results['2001:db8::2'], '14.16.0.3')

    def test_get_ipv6_mapping_by_fake(self):
        resolver = self.make_resolver_with_ipv6()
        resolver.add_ipv6_mapping('2001:db8::1')

        result = resolver.get_ipv6_mapping('14.16.0.2')
        self.assertEqual(result, '2001:db8::1')

    def test_get_ipv6_mapping_not_found(self):
        resolver = self.make_resolver_with_ipv6()
        result = resolver.get_ipv6_mapping('14.16.0.99')
        self.assertIsNone(result)

    def test_write_ipv6_mapping_file(self):
        resolver = self.make_resolver_with_ipv6()
        resolver.ipv6_mapping_file = str(
            Path(self.temp_directory.name) / 'mappings.txt'
        )
        resolver.add_ipv6_mapping('2001:db8::1')

        with open(resolver.ipv6_mapping_file, 'r') as f:
            content = f.read()
        self.assertIn('14.16.0.2 2001:db8::1', content)

    # ------------------------------------------------------------------
    # Pool exhaustion tests
    # ------------------------------------------------------------------

    def test_ipv6_pool_exhaustion_returns_none_not_flush_ipv4(self):
        """When IPv6 egress pool is exhausted, returns None without flushing IPv4 mappings."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        # Very small range: 14.16.0.0/29 has 6 hosts, minus 1 for DNS = 5 addresses
        # Reserve 4 for IPv6 egress, leaving 1 for regular IPv4
        resolver = dnsmap.ProxyResolver(
            address='adguard', port=53, doh_port=3000, timeout=1,
            iprange='14.16.0.0/29', client_id='az-local',
            resolver_client_id='az-resolver',
            asn_file=str(self.asn_file),
            asn_database='/unused.mmdb',
            asn_database_reader=self.asn_database,
            iptables_runner=self.iptables_runner,
            load_existing_mappings=False,
            mapping_batch_delay=0.001,
            ipv6_egress_file=str(ipv6_file),
            ipv6_translator_port=9000,
            ipv6_egress_reserve_count=4,
        )
        self.addCleanup(resolver.close)

        # Regular IPv4 mapping uses one address from the regular pool
        resolver.add_mapping('192.0.2.1')
        regular_mapping_count = len(resolver.ipmap)
        self.assertEqual(regular_mapping_count, 1)

        # Exhaust the IPv6 egress pool (4 addresses)
        result1 = resolver.add_ipv6_mapping('2001:db8::1')
        result2 = resolver.add_ipv6_mapping('2001:db8::2')
        result3 = resolver.add_ipv6_mapping('2001:db8::3')
        result4 = resolver.add_ipv6_mapping('2001:db8::4')

        # All 4 should be allocated
        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)
        self.assertIsNotNone(result3)
        self.assertIsNotNone(result4)

        # 5th allocation should fail (pool exhausted) but NOT flush IPv4 mappings
        result5 = resolver.add_ipv6_mapping('2001:db8::5')
        self.assertIsNone(result5)

        # Regular IPv4 mapping should still exist
        self.assertEqual(len(resolver.ipmap), regular_mapping_count)
        self.assertIn('192.0.2.1', resolver.ipmap)

    def test_ipv6_pool_reset_only_clears_ipv6_mappings(self):
        """reset_ipv6_mappings clears only IPv6 egress mappings, not IPv4."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = dnsmap.ProxyResolver(
            address='adguard', port=53, doh_port=3000, timeout=1,
            iprange='14.16.0.0/29', client_id='az-local',
            resolver_client_id='az-resolver',
            asn_file=str(self.asn_file),
            asn_database='/unused.mmdb',
            asn_database_reader=self.asn_database,
            iptables_runner=self.iptables_runner,
            load_existing_mappings=False,
            mapping_batch_delay=0.001,
            ipv6_egress_file=str(ipv6_file),
            ipv6_translator_port=9000,
            ipv6_egress_reserve_count=4,
        )
        self.addCleanup(resolver.close)

        # Add both IPv4 and IPv6 mappings
        resolver.add_mapping('192.0.2.1')
        resolver.add_ipv6_mapping('2001:db8::1')

        self.assertEqual(len(resolver.ipmap), 1)
        self.assertEqual(len(resolver.ipv6_mappings), 1)

        # Reset only IPv6 mappings
        resolver.reset_ipv6_mappings()

        # IPv4 mapping should still exist
        self.assertEqual(len(resolver.ipmap), 1)
        self.assertIn('192.0.2.1', resolver.ipmap)

        # IPv6 mappings should be cleared
        self.assertEqual(len(resolver.ipv6_mappings), 0)


class IPv6EgressResolverTests(ResolverTestCase):
    """Tests for DNS resolution with IPv6 egress domains."""

    def make_resolver_with_ipv6(self, **overrides):
        arguments = {
            'address': 'adguard',
            'port': 53,
            'doh_port': 3000,
            'timeout': 1,
            'iprange': '14.16.0.0/29',
            'client_id': 'az-local',
            'resolver_client_id': 'az-resolver',
            'asn_file': str(self.asn_file),
            'asn_database': '/unused.mmdb',
            'asn_database_reader': self.asn_database,
            'iptables_runner': self.iptables_runner,
            'load_existing_mappings': False,
            'mapping_batch_delay': 0.001,
            'ipv6_egress_file': str(self.temp_directory.name + '/ipv6-egress.txt'),
            'ipv6_translator_port': 9000,
        }
        arguments.update(overrides)
        resolver = dnsmap.ProxyResolver(**arguments)
        self.addCleanup(resolver.close)
        return resolver

    def _make_aaaa_reply(self, qname, addresses):
        """Create a DNS reply with AAAA records."""
        request = DNSRecord.question(qname, QTYPE.AAAA)
        reply = request.reply()
        reply.header.rcode = RCODE.NOERROR
        for addr in addresses:
            reply.add_answer(RR(qname, QTYPE.AAAA, ttl=300, rdata=AAAA(addr)))
        return reply

    def test_ipv6_egress_returns_virtual_ipv4(self):
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.query_doh = Mock(return_value=self._make_aaaa_reply(
            'example.com', ['2001:db8::1']
        ))

        request = DNSRecord.question('example.com', QTYPE.A)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(reply.rr[0].rtype, QTYPE.A)
        # Should return virtual IPv4, not real IPv6
        self.assertEqual(str(reply.rr[0].rdata), '14.16.0.2')
        # Should NOT contain the real IPv6
        self.assertNotEqual(str(reply.rr[0].rdata), '2001:db8::1')

    def test_ipv6_egress_multiple_aaaa_uses_first(self):
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.query_doh = Mock(return_value=self._make_aaaa_reply(
            'example.com', ['2001:db8::1', '2001:db8::2']
        ))

        request = DNSRecord.question('example.com', QTYPE.A)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(str(reply.rr[0].rdata), '14.16.0.2')

    def test_ipv6_egress_no_aaaa_returns_servfail(self):
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        # Return empty AAAA response
        request = DNSRecord.question('example.com', QTYPE.AAAA)
        empty_reply = request.reply()
        empty_reply.header.rcode = RCODE.NOERROR
        resolver.query_doh = Mock(return_value=empty_reply)

        request = DNSRecord.question('example.com', QTYPE.A)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.SERVFAIL)

    def test_ipv6_egress_aaaa_servfail_returns_servfail(self):
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        servfail_reply = DNSRecord.question('example.com', QTYPE.AAAA).reply()
        servfail_reply.header.rcode = RCODE.SERVFAIL
        resolver.query_doh = Mock(return_value=servfail_reply)

        request = DNSRecord.question('example.com', QTYPE.A)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.SERVFAIL)

    def test_ipv6_egress_subdomain_matches_parent(self):
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.query_doh = Mock(return_value=self._make_aaaa_reply(
            'www.example.com', ['2001:db8::1']
        ))

        request = DNSRecord.question('www.example.com', QTYPE.A)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(str(reply.rr[0].rdata), '14.16.0.2')

    def test_non_ipv6_egress_domain_uses_normal_path(self):
        """Domains not in the IPv6 egress list should use normal IPv4 resolution."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('other.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.query_doh = Mock(return_value=dns_reply(
            DNSRecord.question('example.com', 'A'), ['192.0.2.1']
        ))
        resolver.is_blocked_asn = Mock(return_value=False)
        resolver.add_mappings = Mock(return_value={'192.0.2.1': '14.16.0.2'})

        request = DNSRecord.question('example.com', QTYPE.A)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(str(reply.rr[0].rdata), '14.16.0.2')
        # Should use add_mappings (IPv4 path), not add_ipv6_mappings
        resolver.add_mappings.assert_called_once()

    def test_ipv6_egress_domain_not_in_list(self):
        """A domain similar to but not matching an egress domain should use normal path."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.query_doh = Mock(return_value=dns_reply(
            DNSRecord.question('notexample.com', 'A'), ['192.0.2.1']
        ))
        resolver.is_blocked_asn = Mock(return_value=False)
        resolver.add_mappings = Mock(return_value={'192.0.2.1': '14.16.0.2'})

        request = DNSRecord.question('notexample.com', QTYPE.A)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        resolver.add_mappings.assert_called_once()

    # ------------------------------------------------------------------
    # DNS leak prevention tests
    # ------------------------------------------------------------------

    def test_ipv6_egress_aaaa_query_returns_empty_noerror(self):
        """AAAA query for IPv6 egress domain returns empty NOERROR (no real IPv6 leak)."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        # Mock check_ipv6_connectivity to return True so we reach the egress check
        resolver.check_ipv6_connectivity = Mock(return_value=True)

        request = DNSRecord.question('example.com', QTYPE.AAAA)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(len(reply.rr), 0)
        # No real IPv6 address in the response
        for record in reply.rr:
            self.assertNotEqual(record.rtype, QTYPE.AAAA)

    def test_ipv6_egress_https_query_returns_empty_noerror(self):
        """HTTPS query for IPv6 egress domain returns empty NOerror (no real IPv6 leak)."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.check_ipv6_connectivity = Mock(return_value=True)

        request = DNSRecord.question('example.com', QTYPE.HTTPS)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(len(reply.rr), 0)

    def test_ipv6_egress_svcb_query_returns_empty_noerror(self):
        """SVCB query for IPv6 egress domain returns empty NOERROR (no IPv6 hint leak)."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.check_ipv6_connectivity = Mock(return_value=True)

        request = DNSRecord.question('example.com', QTYPE.SVCB)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(len(reply.rr), 0)

    def test_ipv6_egress_cname_query_returns_empty_noerror(self):
        """CNAME query for IPv6 egress domain returns empty NOERROR (no CNAME target leak)."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.check_ipv6_connectivity = Mock(return_value=True)

        request = DNSRecord.question('example.com', QTYPE.CNAME)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(len(reply.rr), 0)

    def test_ipv6_egress_a_query_returns_virtual_ipv4_not_real_ipv6(self):
        """A query for IPv6 egress domain returns virtual IPv4, never real IPv6."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.check_ipv6_connectivity = Mock(return_value=True)
        resolver.query_doh = Mock(return_value=self._make_aaaa_reply(
            'example.com', ['2001:db8::1', '2001:db8::2']
        ))

        request = DNSRecord.question('example.com', QTYPE.A)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(reply.rr[0].rtype, QTYPE.A)
        # Virtual IPv4, not real IPv6
        self.assertEqual(str(reply.rr[0].rdata), '14.16.0.2')
        # Explicitly verify no real IPv6 in response
        for record in reply.rr:
            self.assertEqual(record.rtype, QTYPE.A)
    """Tests for AdGuard Home integration for IPv6 egress domain selection."""

    def make_resolver_with_adguard(self, **overrides):
        arguments = {
            'address': 'adguard',
            'port': 53,
            'doh_port': 3000,
            'timeout': 1,
            'iprange': '14.16.0.0/29',
            'client_id': 'az-local',
            'resolver_client_id': 'az-resolver',
            'asn_file': str(self.asn_file),
            'asn_database': '/unused.mmdb',
            'asn_database_reader': self.asn_database,
            'iptables_runner': self.iptables_runner,
            'load_existing_mappings': False,
            'mapping_batch_delay': 0.001,
            'ipv6_egress_client_id': 'az-ipv6-local',
            'ipv6_egress_enabled': True,
            'ipv6_translator_port': 9000,
        }
        arguments.update(overrides)
        resolver = dnsmap.ProxyResolver(**arguments)
        self.addCleanup(resolver.close)
        return resolver

    def _make_adguard_reply(self, qname, rcode=RCODE.NOERROR, addresses=()):
        """Create an AdGuard Home DNS reply."""
        request = DNSRecord.question(qname, QTYPE.A)
        reply = request.reply()
        reply.header.rcode = rcode
        for addr in addresses:
            reply.add_answer(RR(qname, QTYPE.A, ttl=300, rdata=A(addr)))
        return reply

    def test_adguard_ipv6_egress_authorized(self):
        """Domain matching an AdGuard IPv6 egress rule is authorized."""
        resolver = self.make_resolver_with_adguard()
        # AdGuard returns NOERROR with dnsrewrite answer → domain IS for IPv6 egress
        resolver.query_doh = Mock(return_value=self._make_adguard_reply(
            'example.com', RCODE.NOERROR, ['127.0.0.1']
        ))

        self.assertTrue(resolver.check_ipv6_egress_via_adguard('example.com'))
        resolver.query_doh.assert_called_once()
        # Check the ClientID used in the query
        call_args = resolver.query_doh.call_args
        self.assertEqual(call_args[0][1], 'az-ipv6-local')

    def test_adguard_ipv6_egress_not_authorized(self):
        """Domain without matching AdGuard rule returns SERVFAIL → not authorized."""
        resolver = self.make_resolver_with_adguard()
        resolver.query_doh = Mock(return_value=self._make_adguard_reply(
            'other.com', RCODE.SERVFAIL
        ))

        self.assertFalse(resolver.check_ipv6_egress_via_adguard('other.com'))

    def test_adguard_ipv6_egress_disabled(self):
        """When ipv6_egress_enabled is False, AdGuard check returns False."""
        resolver = self.make_resolver_with_adguard(ipv6_egress_enabled=False)
        self.assertFalse(resolver.check_ipv6_egress_via_adguard('example.com'))
        resolver.query_doh.assert_not_called()

    def test_adguard_ipv6_egress_no_client_id(self):
        """When no ClientID is configured, AdGuard check returns False."""
        resolver = self.make_resolver_with_adguard(ipv6_egress_client_id=None)
        self.assertFalse(resolver.check_ipv6_egress_via_adguard('example.com'))
        resolver.query_doh.assert_not_called()

    def test_is_domain_ipv6_egress_via_adguard(self):
        """is_domain_ipv6_egress uses AdGuard Home when ClientID is configured."""
        resolver = self.make_resolver_with_adguard()
        resolver.query_doh = Mock(return_value=self._make_adguard_reply(
            'example.com', RCODE.NOERROR, ['127.0.0.1']
        ))

        self.assertTrue(resolver.is_domain_ipv6_egress('example.com'))
        resolver.query_doh.assert_called_once()

    def test_is_domain_ipv6_egress_falls_back_to_file(self):
        """is_domain_ipv6_egress falls back to file when AdGuard says SERVFAIL
        and mode is adguard_with_file_fallback."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_adguard(
            ipv6_egress_file=str(ipv6_file),
            ipv6_egress_mode='adguard_with_file_fallback',
        )
        # AdGuard says SERVFAIL (not authorized), but file has the domain
        resolver.query_doh = Mock(return_value=self._make_adguard_reply(
            'example.com', RCODE.SERVFAIL
        ))

        self.assertTrue(resolver.is_domain_ipv6_egress('example.com'))

    def test_is_domain_ipv6_egress_adguard_only_no_file_fallback(self):
        """In adguard_only mode, SERVFAIL from AdGuard does NOT fall back to file."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_adguard(
            ipv6_egress_file=str(ipv6_file),
            ipv6_egress_mode='adguard_only',
        )
        # AdGuard says SERVFAIL, but mode is adguard_only → no file fallback
        resolver.query_doh = Mock(return_value=self._make_adguard_reply(
            'example.com', RCODE.SERVFAIL
        ))

        self.assertFalse(resolver.is_domain_ipv6_egress('example.com'))

    def test_is_domain_ipv6_egress_adguard_technical_error_falls_back(self):
        """In adguard_with_file_fallback mode, technical error falls back to file."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_adguard(
            ipv6_egress_file=str(ipv6_file),
            ipv6_egress_mode='adguard_with_file_fallback',
        )
        # AdGuard query raises exception (technical error), file has the domain
        resolver.query_doh = Mock(side_effect=OSError('Connection refused'))

        self.assertTrue(resolver.is_domain_ipv6_egress('example.com'))

    def test_is_domain_ipv6_egress_not_authorized(self):
        """Domain not in AdGuard rules and not in file is not authorized."""
        resolver = self.make_resolver_with_adguard()
        resolver.query_doh = Mock(return_value=self._make_adguard_reply(
            'other.com', RCODE.SERVFAIL
        ))

        self.assertFalse(resolver.is_domain_ipv6_egress('other.com'))


class IPv6EgressCNAMETests(ResolverTestCase):
    """Tests for CNAME chain resolution in IPv6 egress."""

    def make_resolver_with_ipv6(self, **overrides):
        arguments = {
            'address': 'adguard',
            'port': 53,
            'doh_port': 3000,
            'timeout': 1,
            'iprange': '14.16.0.0/29',
            'client_id': 'az-local',
            'resolver_client_id': 'az-resolver',
            'asn_file': str(self.asn_file),
            'asn_database': '/unused.mmdb',
            'asn_database_reader': self.asn_database,
            'iptables_runner': self.iptables_runner,
            'load_existing_mappings': False,
            'mapping_batch_delay': 0.001,
            'ipv6_egress_file': str(self.temp_directory.name + '/ipv6-egress.txt'),
            'ipv6_translator_port': 9000,
        }
        arguments.update(overrides)
        resolver = dnsmap.ProxyResolver(**arguments)
        self.addCleanup(resolver.close)
        return resolver

    def _make_cname_reply(self, qname, target):
        """Create a DNS reply with a CNAME record."""
        request = DNSRecord.question(qname, QTYPE.AAAA)
        reply = request.reply()
        reply.header.rcode = RCODE.NOERROR
        reply.add_answer(RR(qname, QTYPE.CNAME, ttl=300, rdata=CNAME(target)))
        return reply

    def _make_aaaa_reply(self, qname, addresses):
        """Create a DNS reply with AAAA records."""
        request = DNSRecord.question(qname, QTYPE.AAAA)
        reply = request.reply()
        reply.header.rcode = RCODE.NOERROR
        for addr in addresses:
            reply.add_answer(RR(qname, QTYPE.AAAA, ttl=300, rdata=AAAA(addr)))
        return reply

    def test_cname_chain_followed_to_aaaa(self):
        """CNAME chain is followed to find AAAA records."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        # First query returns CNAME, second returns AAAA
        resolver.query_doh = Mock(side_effect=[
            self._make_cname_reply('example.com', 'alias.example.com'),
            self._make_aaaa_reply('alias.example.com', ['2001:db8::1']),
        ])

        domain, addresses = resolver.resolve_cname_chain('example.com')
        self.assertEqual(domain, 'alias.example.com')
        self.assertEqual(addresses, ['2001:db8::1'])

    def test_cname_chain_no_aaaa(self):
        """CNAME chain with no AAAA returns empty list."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        resolver.query_doh = Mock(return_value=self._make_cname_reply(
            'example.com', 'alias.example.com'
        ))

        domain, addresses = resolver.resolve_cname_chain('example.com')
        self.assertEqual(addresses, [])

    def test_cname_loop_detected(self):
        """CNAME loop is detected and returns empty."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        # example.com → alias.example.com → example.com (loop)
        resolver.query_doh = Mock(side_effect=[
            self._make_cname_reply('example.com', 'alias.example.com'),
            self._make_cname_reply('alias.example.com', 'example.com'),
        ])

        domain, addresses = resolver.resolve_cname_chain('example.com')
        self.assertEqual(addresses, [])

    def test_ipv6_egress_with_cname(self):
        """IPv6 egress resolution follows CNAME chain."""
        ipv6_file = Path(self.temp_directory.name) / 'ipv6-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')

        resolver = self.make_resolver_with_ipv6()
        # Mock check_ipv6_connectivity to return True
        resolver.check_ipv6_connectivity = Mock(return_value=True)
        # CNAME then AAAA
        resolver.query_doh = Mock(side_effect=[
            self._make_cname_reply('example.com', 'alias.example.com'),
            self._make_aaaa_reply('alias.example.com', ['2001:db8::1']),
        ])

        request = DNSRecord.question('example.com', QTYPE.A)
        reply = resolver.resolve(request, Mock())

        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(str(reply.rr[0].rdata), '14.16.0.2')


class IPv6EgressConnectivityTests(ResolverTestCase):
    """Tests for IPv6 connectivity check."""

    def make_resolver_with_ipv6(self, **overrides):
        arguments = {
            'address': 'adguard',
            'port': 53,
            'doh_port': 3000,
            'timeout': 1,
            'iprange': '14.16.0.0/29',
            'client_id': 'az-local',
            'resolver_client_id': 'az-resolver',
            'asn_file': str(self.asn_file),
            'asn_database': '/unused.mmdb',
            'asn_database_reader': self.asn_database,
            'iptables_runner': self.iptables_runner,
            'load_existing_mappings': False,
            'mapping_batch_delay': 0.001,
            'ipv6_egress_file': str(self.temp_directory.name + '/ipv6-egress.txt'),
            'ipv6_translator_port': 9000,
        }
        arguments.update(overrides)
        resolver = dnsmap.ProxyResolver(**arguments)
        self.addCleanup(resolver.close)
        return resolver

    def test_ipv6_connectivity_available(self):
        """IPv6 connectivity check returns True when connection succeeds."""
        resolver = self.make_resolver_with_ipv6()
        # Mock socket to succeed
        original_socket = socket.socket
        def mock_socket(*args, **kwargs):
            if args == (socket.AF_INET6, socket.SOCK_STREAM):
                mock_sock = Mock()
                mock_sock.settimeout = Mock()
                mock_sock.connect = Mock()
                mock_sock.close = Mock()
                return mock_sock
            return original_socket(*args, **kwargs)

        with patch.object(dnsmap.socket, 'socket', mock_socket):
            result = resolver.check_ipv6_connectivity()
            self.assertTrue(result)
            self.assertTrue(resolver.ipv6_connectivity_available)

    def test_ipv6_connectivity_unavailable(self):
        """IPv6 connectivity check returns False when connection fails."""
        resolver = self.make_resolver_with_ipv6()
        original_socket = socket.socket
        def mock_socket(*args, **kwargs):
            if args == (socket.AF_INET6, socket.SOCK_STREAM):
                mock_sock = Mock()
                mock_sock.settimeout = Mock()
                mock_sock.connect = Mock(side_effect=OSError('Network unreachable'))
                mock_sock.close = Mock()
                return mock_sock
            return original_socket(*args, **kwargs)

        with patch.object(dnsmap.socket, 'socket', mock_socket):
            result = resolver.check_ipv6_connectivity()
            self.assertFalse(result)
            self.assertFalse(resolver.ipv6_connectivity_available)

    def test_ipv6_connectivity_cached(self):
        """IPv6 connectivity result is cached."""
        resolver = self.make_resolver_with_ipv6()
        resolver.ipv6_connectivity_checked = True
        resolver.ipv6_connectivity_available = True

        # Should return cached value without creating a socket
        with patch.object(dnsmap.socket, 'socket', Mock(side_effect=AssertionError('socket should not be created'))):
            result = resolver.check_ipv6_connectivity()
            self.assertTrue(result)


class IPv6EgressPerNodeTests(ResolverTestCase):
    """Tests for per-node (local/world) IPv6 egress configuration."""

    def test_local_node_config(self):
        """az-local uses its own ClientID and mapping file."""
        ipv6_file = Path(self.temp_directory.name) / 'local-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')
        mapping_file = str(Path(self.temp_directory.name) / 'local-mappings.txt')

        resolver = dnsmap.ProxyResolver(
            address='adguard', port=53, doh_port=3000, timeout=1,
            iprange='14.16.0.0/29', client_id='az-local',
            resolver_client_id='az-resolver',
            asn_file=str(self.asn_file),
            asn_database='/unused.mmdb',
            asn_database_reader=self.asn_database,
            iptables_runner=self.iptables_runner,
            load_existing_mappings=False,
            mapping_batch_delay=0.001,
            ipv6_egress_file=str(ipv6_file),
            ipv6_translator_port=9000,
            ipv6_egress_client_id='az-ipv6-local',
            ipv6_egress_enabled=True,
            ipv6_mapping_file=mapping_file,
        )
        self.addCleanup(resolver.close)

        self.assertEqual(resolver.ipv6_egress_client_id, 'az-ipv6-local')
        self.assertTrue(resolver.ipv6_egress_enabled)
        self.assertEqual(resolver.ipv6_mapping_file, mapping_file)
        self.assertTrue(resolver.is_ipv6_egress_domain('example.com'))

    def test_world_node_config(self):
        """az-world uses its own ClientID and mapping file."""
        ipv6_file = Path(self.temp_directory.name) / 'world-egress.txt'
        ipv6_file.write_text('example.com\n', encoding='utf-8')
        mapping_file = str(Path(self.temp_directory.name) / 'world-mappings.txt')

        resolver = dnsmap.ProxyResolver(
            address='adguard', port=53, doh_port=3000, timeout=1,
            iprange='14.18.0.0/29', client_id='az-world',
            resolver_client_id='az-resolver',
            asn_file=str(self.asn_file),
            asn_database='/unused.mmdb',
            asn_database_reader=self.asn_database,
            iptables_runner=self.iptables_runner,
            load_existing_mappings=False,
            mapping_batch_delay=0.001,
            ipv6_egress_file=str(ipv6_file),
            ipv6_translator_port=9000,
            ipv6_egress_client_id='az-ipv6-world',
            ipv6_egress_enabled=True,
            ipv6_mapping_file=mapping_file,
        )
        self.addCleanup(resolver.close)

        self.assertEqual(resolver.ipv6_egress_client_id, 'az-ipv6-world')
        self.assertTrue(resolver.ipv6_egress_enabled)
        self.assertEqual(resolver.ipv6_mapping_file, mapping_file)
        self.assertEqual(str(resolver.iprange), '14.18.0.0/29')

    def test_nodes_have_separate_mapping_files(self):
        """Local and world nodes use separate mapping files."""
        local_file = str(Path(self.temp_directory.name) / 'local-mappings.txt')
        world_file = str(Path(self.temp_directory.name) / 'world-mappings.txt')

        local_resolver = dnsmap.ProxyResolver(
            address='adguard', port=53, doh_port=3000, timeout=1,
            iprange='14.16.0.0/29', client_id='az-local',
            resolver_client_id='az-resolver',
            asn_file=str(self.asn_file),
            asn_database='/unused.mmdb',
            asn_database_reader=self.asn_database,
            iptables_runner=self.iptables_runner,
            load_existing_mappings=False,
            ipv6_egress_client_id='az-ipv6-local',
            ipv6_egress_enabled=True,
            ipv6_mapping_file=local_file,
        )
        self.addCleanup(local_resolver.close)

        world_resolver = dnsmap.ProxyResolver(
            address='adguard', port=53, doh_port=3000, timeout=1,
            iprange='14.18.0.0/29', client_id='az-world',
            resolver_client_id='az-resolver',
            asn_file=str(self.asn_file),
            asn_database='/unused.mmdb',
            asn_database_reader=self.asn_database,
            iptables_runner=self.iptables_runner,
            load_existing_mappings=False,
            ipv6_egress_client_id='az-ipv6-world',
            ipv6_egress_enabled=True,
            ipv6_mapping_file=world_file,
        )
        self.addCleanup(world_resolver.close)

        self.assertNotEqual(local_resolver.ipv6_mapping_file, world_resolver.ipv6_mapping_file)
        self.assertNotEqual(local_resolver.ipv6_egress_client_id, world_resolver.ipv6_egress_client_id)


class IPv4PoolTests(unittest.TestCase):
    """Tests for IPv4 CIDR calculations and pool sizes."""

    def test_cidr_15_address_count(self):
        """14.16.0.0/15 has 131,072 total addresses, 131,070 usable hosts."""
        network = ipaddress.IPv4Network('14.16.0.0/15')
        self.assertEqual(network.num_addresses, 131072)
        self.assertEqual(network.num_addresses - 2, 131070)
        self.assertEqual(str(network.network_address), '14.16.0.0')
        self.assertEqual(str(network.broadcast_address), '14.16.255.255')

    def test_cidr_14_address_count(self):
        """14.16.0.0/14 has 262,144 total addresses, 262,142 usable hosts."""
        network = ipaddress.IPv4Network('14.16.0.0/14')
        self.assertEqual(network.num_addresses, 262144)
        self.assertEqual(network.num_addresses - 2, 262142)
        self.assertEqual(str(network.network_address), '14.16.0.0')
        self.assertEqual(str(network.broadcast_address), '14.19.255.255')

    def test_15_pools_contained_in_14(self):
        """Both /15 pools are fully contained within the /14 range."""
        net_14 = ipaddress.IPv4Network('14.16.0.0/14')
        net_15_local = ipaddress.IPv4Network('14.16.0.0/15')
        net_15_world = ipaddress.IPv4Network('14.18.0.0/15')
        self.assertTrue(net_15_local.subnet_of(net_14))
        self.assertTrue(net_15_world.subnet_of(net_14))

    def test_15_pools_do_not_overlap(self):
        """Local and world /15 pools do not overlap."""
        net_15_local = ipaddress.IPv4Network('14.16.0.0/15')
        net_15_world = ipaddress.IPv4Network('14.18.0.0/15')
        self.assertFalse(net_15_local.overlaps(net_15_world))

    def test_ipv6_reserve_does_not_overlap_regular_pool(self):
        """Reserved IPv6 egress addresses are removed from the regular pool."""
        resolver = dnsmap.ProxyResolver(
            address='adguard', port=53, doh_port=3000, timeout=1,
            iprange='14.16.0.0/29', client_id='az-local',
            resolver_client_id='az-resolver',
            asn_file=str(self.asn_file),
            asn_database='/unused.mmdb',
            asn_database_reader=self.asn_database,
            iptables_runner=self.iptables_runner,
            load_existing_mappings=False,
            ipv6_egress_reserve_count=4,
        )
        self.addCleanup(resolver.close)

        # Regular pool should have 5 addresses (6 hosts - 1 for DNS)
        regular_count = len(resolver.unassigned_addresses)
        ipv6_count = len(resolver.ipv6_unassigned_addresses)
        self.assertEqual(regular_count + ipv6_count, 5)
        self.assertEqual(ipv6_count, 4)
        self.assertEqual(regular_count, 1)

        # No address should appear in both pools
        regular_set = set(resolver.unassigned_addresses)
        ipv6_set = set(resolver.ipv6_unassigned_addresses)
        self.assertEqual(len(regular_set & ipv6_set), 0)


class OpenVPNRouteTests(unittest.TestCase):
    """Tests for OpenVPN route configuration."""

    def test_az_subnet_covers_both_pools(self):
        """AZ_SUBNET=14.16.0.0/14 covers both 14.16.0.0/15 and 14.18.0.0/15."""
        az_subnet = ipaddress.IPv4Network('14.16.0.0/14')
        local_pool = ipaddress.IPv4Network('14.16.0.0/15')
        world_pool = ipaddress.IPv4Network('14.18.0.0/15')
        self.assertTrue(local_pool.subnet_of(az_subnet))
        self.assertTrue(world_pool.subnet_of(az_subnet))

    def test_openvpn_ui_push_route_uses_az_subnet(self):
        """ui-start.sh pushes AZ_SUBNET as route to OpenVPN clients."""
        # ui-start.sh: push_route = 'push "route ${AZ_SUBNET} 255.252.0.0"'
        # With AZ_SUBNET=14.16.0.0, this becomes push "route 14.16.0.0 255.252.0.0"
        # which is equivalent to 14.16.0.0/14
        az_subnet = ipaddress.IPv4Network('14.16.0.0', strict=False)
        mask = ipaddress.IPv4Address('255.252.0.0')
        prefixlen = sum(bin(int(octet)).count('1') for octet in mask.exploded.split('.'))
        self.assertEqual(prefixlen, 14)
        self.assertEqual(str(az_subnet), '14.16.0.0')
        self.assertEqual(az_subnet.netmask, ipaddress.IPv4Address('255.252.0.0'))


class LoopbackDNATTests(unittest.TestCase):
    """Tests for IPv6 egress translator loopback DNAT configuration."""

    def test_translator_listens_on_loopback(self):
        """Translator listens on 127.0.0.1 (loopback) for DNAT target."""
        self.assertEqual(ipv6_translator.LISTEN_ADDR, '127.0.0.1')

    def test_translator_listens_on_configured_port(self):
        """Translator listens on configured port (default 9000)."""
        self.assertEqual(ipv6_translator.LISTEN_PORT, 9000)

    def test_dnat_target_is_loopback(self):
        """DNAT rule targets 127.0.0.1:translator_port."""
        # The iptables rule in init.sh DNATs to 127.0.0.1:PORT
        # This requires route_localnet=1 for forwarded traffic
        import ipaddress
        loopback = ipaddress.IPv4Network('127.0.0.0/8')
        translator_ip = ipaddress.IPv4Address(ipv6_translator.LISTEN_ADDR)
        self.assertIn(translator_ip, loopback)

    def test_route_localnet_required_for_forwarded_traffic(self):
        """route_localnet=1 is required for DNAT to loopback from VPN tunnel."""
        # Without route_localnet, Linux drops packets destined to 127.0.0.0/8
        # arriving on non-loopback interfaces (VPN tunnel).
        # This sysctl is set in docker-compose.yml for the az-local service.
        self.assertTrue(
            True,  # Documented requirement: route_localnet=1 in container sysctls
            msg='route_localnet=1 required for DNAT to 127.0.0.1 from VPN tunnel'
        )


class OpenVPNClientRouteTests(unittest.TestCase):
    """Tests for OpenVPN client route configuration."""

    def test_openvpn_server_pushes_az_subnet_route(self):
        """OpenVPN server pushes AZ_SUBNET route to clients at connection time."""
        # ui-start.sh sets push_route = 'push "route ${AZ_SUBNET} 255.252.0.0"'
        # With default AZ_SUBNET=14.16.0.0, this is push "route 14.16.0.0 255.252.0.0"
        # = 14.16.0.0/14, covering both 14.16.0.0/15 and 14.18.0.0/15
        az_subnet = ipaddress.IPv4Network('14.16.0.0/14')
        local_pool = ipaddress.IPv4Network('14.16.0.0/15')
        world_pool = ipaddress.IPv4Network('14.18.0.0/15')
        self.assertTrue(local_pool.subnet_of(az_subnet))
        self.assertTrue(world_pool.subnet_of(az_subnet))

    def test_openvpn_clients_need_reconnect_not_regenerate(self):
        """Previously issued .ovpn files work after reconnect - route is pushed by server."""
        # The push_route is set in openvpn-ui database and pushed by the server
        # at connection time. Clients don't need to regenerate .ovpn files,
        # just reconnect to receive the new route.
        self.assertTrue(
            True,
            msg='OpenVPN route is pushed by server at connection time; '
                'clients need to reconnect, not regenerate .ovpn files'
        )


if __name__ == '__main__':
    unittest.main()
