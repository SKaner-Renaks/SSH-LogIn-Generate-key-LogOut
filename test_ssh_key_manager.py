import unittest
from unittest.mock import MagicMock, patch, mock_open
import os
import sys
import ssh_key_manager

class TestSSHKeyManager(unittest.TestCase):

    @patch('ssh_key_manager.paramiko.SSHClient')
    @patch('ssh_key_manager.os.path.exists')
    @patch('ssh_key_manager.datetime.datetime')
    def test_connect_and_setup_ssh_key_success(self, mock_datetime, mock_exists, mock_ssh_client):
        # Mocking
        mock_datetime.now.return_value.strftime.return_value = "10:00:00"
        mock_exists.return_value = True # Local key exists

        mock_ssh = MagicMock()
        mock_ssh_client.return_value = mock_ssh

        # Test
        result = ssh_key_manager.connect_and_setup_ssh(
            "host", "user", None, "/local/keys", "/root", server_name="proxmox1"
        )

        # Assertions
        mock_ssh.connect.assert_called_once_with(
            "host", username="user", key_filename=os.path.join("/local/keys", "id_rsa_proxmox1"), timeout=10
        )
        self.assertEqual(result, mock_ssh)

    @patch('ssh_key_manager.paramiko.SSHClient')
    @patch('ssh_key_manager.os.path.exists')
    @patch('ssh_key_manager.getpass.getpass')
    @patch('ssh_key_manager.paramiko.RSAKey.generate')
    @patch('ssh_key_manager.os.makedirs')
    @patch('ssh_key_manager.os.chmod')
    @patch('ssh_key_manager.open', new_callable=mock_open)
    def test_connect_and_setup_ssh_password_flow(self, mock_file, mock_chmod, mock_makedirs, mock_gen, mock_getpass, mock_exists, mock_ssh_client):
        # Mocking
        mock_exists.return_value = False # No local key
        mock_getpass.return_value = "password123"

        mock_ssh = MagicMock()
        mock_ssh_client.return_value = mock_ssh

        mock_ssh.connect.side_effect = [None] # First call for password

        mock_key = MagicMock()
        mock_key.get_name.return_value = "ssh-rsa"
        mock_key.get_base64.return_value = "BASE64"
        mock_gen.return_value = mock_key

        # Mock outputs for existence checks
        mock_stdout_exists = MagicMock()
        mock_stdout_exists.read.return_value = b"EXISTS\n"
        mock_stdout_exists.channel.recv_exit_status.return_value = 0

        mock_stdout_not_exists = MagicMock()
        mock_stdout_not_exists.read.return_value = b"NOT_EXISTS\n"
        mock_stdout_not_exists.channel.recv_exit_status.return_value = 0

        # Mock for cat authorized_keys
        mock_stdout_cat = MagicMock()
        mock_stdout_cat.read.return_value = b"ssh-rsa OLD_KEY user@otherhost\n"
        mock_stdout_cat.channel.recv_exit_status.return_value = 0

        mock_stdin_append = MagicMock()
        mock_stdout_append = MagicMock()
        mock_stdout_append.channel.recv_exit_status.return_value = 0

        # Side effect to handle multiple exec_command calls
        mock_ssh.exec_command.side_effect = [
            (MagicMock(), mock_stdout_not_exists, MagicMock()), # test -d
            (MagicMock(), MagicMock(), MagicMock()), # mkdir
            (MagicMock(), MagicMock(), MagicMock()), # chmod
            (MagicMock(), mock_stdout_not_exists, MagicMock()), # test -f
            (MagicMock(), MagicMock(), MagicMock()), # touch
            (MagicMock(), MagicMock(), MagicMock()), # chmod
            (MagicMock(), mock_stdout_cat, MagicMock()), # cat
            (mock_stdin_append, mock_stdout_append, MagicMock()), # cat >>
        ]

        # Test
        result = ssh_key_manager.connect_and_setup_ssh(
            "host", "user", None, "/local/keys", "/root", server_name="proxmox1"
        )

        # Assertions
        mock_ssh.connect.assert_called_with("host", username="user", password="password123", timeout=10)
        mock_gen.assert_called_once_with(4096)

        # Verify key was saved using write_private_key_file (OpenSSH format)
        mock_key.write_private_key_file.assert_called_once()

        # Check if mkdir and touch were called because we mocked NOT_EXISTS
        calls = [c.args[0] for c in mock_ssh.exec_command.call_args_list]
        self.assertTrue(any("mkdir -p /root/.ssh" in cmd for cmd in calls))
        self.assertTrue(any("touch /root/.ssh/authorized_keys" in cmd for cmd in calls))
        self.assertTrue(any("cat >> /root/.ssh/authorized_keys" in cmd for cmd in calls))

        # Verify key with comment was written to append
        expected_key = "ssh-rsa BASE64 user@host"
        mock_stdin_append.write.assert_any_call(f"\n{expected_key}\n")

    @patch('ssh_key_manager.connect_and_setup_ssh')
    @patch('ssh_key_manager.test_connection')
    @patch('ssh_key_manager.disconnect_ssh')
    @patch('ssh_key_manager.sys.exit')
    def test_main_loop(self, mock_exit, mock_disconnect, mock_test, mock_connect):
        # Setup SERVERS for test
        ssh_key_manager.SERVERS = [
            {"name": "s1", "host": "h1", "username": "u1", "password": "p1", "remote_home": "/r1"},
            {"name": "s2", "host": "h2", "username": "u2", "password": None, "remote_home": "/r2"}
        ]

        mock_connect.side_effect = [MagicMock(), Exception("Fail")]

        ssh_key_manager.main()

        self.assertEqual(mock_connect.call_count, 2)
        self.assertEqual(mock_test.call_count, 1) # s1 success, s2 fail
        self.assertEqual(mock_disconnect.call_count, 1) # s1 success, s2 failed to connect
        mock_exit.assert_called_with(1)

if __name__ == '__main__':
    unittest.main()
