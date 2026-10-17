"""Pending authentication must not prevent native integrations retrying evidence."""
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from babel.account_wake import Receiver
from babel.claude_wake import Channel
from babel.core import BridgeError
from babel.opencode_bridge import Bridge


class EnrollmentRetryIntegrationTests(unittest.TestCase):
    def test_receiver_schedules_evidence_even_if_native_discovery_is_unavailable(self):
        receiver = Receiver.__new__(Receiver)
        receiver.root = Path('/synthetic/account')
        receiver.native = Mock()
        receiver.native.loaded.side_effect = BridgeError('Native runtime not available')
        with patch('babel.account_enrollment.ensure_enrollment', return_value=False) as schedule:
            with self.assertRaises(BridgeError):
                receiver.tick()
        schedule.assert_called_once_with(receiver.root / 'trusted-account.json')

    def test_bound_claude_channel_retries_before_pending_mailbox_authentication(self):
        channel = Channel.__new__(Channel)
        channel.account_file = Path('/synthetic/account/trusted-account.json')
        channel.binding = lambda: '10000000-0000-4000-8000-000000000001'
        channel.root, channel.helper = channel.account_file.parent, Mock()
        with patch('babel.account_enrollment.ensure_enrollment', return_value=False) as schedule:
            with patch('babel.claude_wake.Mailbox', side_effect=BridgeError('Enrollment pending')):
                with self.assertRaises(BridgeError):
                    channel.tick()
        schedule.assert_called_once_with(channel.account_file)

    def test_opencode_native_poll_retries_without_bootstrapping_a_session(self):
        bridge = Bridge.__new__(Bridge)
        bridge.account_file = Path('/synthetic/account/trusted-account.json')
        bridge.root, bridge.helper = bridge.account_file.parent, Mock()
        with patch('babel.account_enrollment.ensure_enrollment', return_value=False) as schedule:
            with patch('babel.opencode_bridge.Mailbox', side_effect=BridgeError('Enrollment pending')):
                with self.assertRaises(BridgeError):
                    bridge.poll('ses_synthetic12345678')
        schedule.assert_called_once_with(bridge.account_file)
        bridge.helper.prepare.assert_not_called()


if __name__ == '__main__':
    unittest.main()
