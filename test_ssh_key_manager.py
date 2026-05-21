import unittest
from unittest.mock import MagicMock, patch, mock_open
import os
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
            "host", "user", None, "/local/keys", "/root"
        )

        # Assertions
        mock_ssh.connect.assert_called_once_with(
            "host", username="user", key_filename=os.path.join("/local/keys", "id_rsa_proxmox"), timeout=10
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

        # Mock exec_command for cat (read keys) returning some existing keys
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"ssh-rsa OLD_KEY user@otherhost\n"
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_stdin_append = MagicMock()
        mock_stdout_append = MagicMock()
        mock_stdout_append.channel.recv_exit_status.return_value = 0

        # Side effect to handle multiple exec_command calls
        # 1. mkdir, 2. chmod, 3. touch, 4. cat, 5. cat >> (append), 6. chmod, 7. chmod
        mock_ssh.exec_command.side_effect = [
            (MagicMock(), MagicMock(), MagicMock()), # mkdir
            (MagicMock(), MagicMock(), MagicMock()), # chmod
            (MagicMock(), MagicMock(), MagicMock()), # touch
            (MagicMock(), mock_stdout, MagicMock()), # cat
            (mock_stdin_append, mock_stdout_append, MagicMock()), # cat >>
            (MagicMock(), MagicMock(), MagicMock()), # chmod
            (MagicMock(), MagicMock(), MagicMock()), # chmod
        ]

        # Test
        result = ssh_key_manager.connect_and_setup_ssh(
            "host", "user", None, "/local/keys", "/root"
        )

        # Assertions
        mock_ssh.connect.assert_called_with("host", username="user", password="password123", timeout=10)
        mock_gen.assert_called_once_with(4096)

        # Verify key was saved using write_private_key
        mock_key.write_private_key.assert_called_once()

        # Check if touch and cat were called
        calls = [c.args[0] for c in mock_ssh.exec_command.call_args_list]
        self.assertTrue(any("touch /root/.ssh/authorized_keys" in cmd for cmd in calls))
        self.assertTrue(any("cat /root/.ssh/authorized_keys" in cmd for cmd in calls))
        self.assertTrue(any("cat >> /root/.ssh/authorized_keys" in cmd for cmd in calls))

        # Verify key with comment was written to append
        expected_key = "ssh-rsa BASE64 user@host"
        mock_stdin_append.write.assert_any_call(f"\n{expected_key}\n")

if __name__ == '__main__':
    unittest.main()
