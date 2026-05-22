import unittest
from unittest.mock import MagicMock, patch, mock_open
import os
import sys
import json
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
            "host", "user", None, "/local/keys", "/root", "test-uuid", server_name="proxmox1", key_size=3072
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
    @patch('ssh_key_manager.sys.stdin.readline')
    @patch('ssh_key_manager.open', new_callable=mock_open)
    @patch('ssh_key_manager.datetime.datetime')
    def test_connect_and_setup_ssh_password_flow_and_cleanup(self, mock_datetime, mock_file, mock_readline, mock_chmod, mock_makedirs, mock_gen, mock_getpass, mock_exists, mock_ssh_client):
        # Mocking
        mock_datetime.now.return_value.strftime.return_value = "2023-01-01_10-00-00"
        mock_exists.return_value = False # No local key
        mock_getpass.return_value = "password123"
        mock_readline.return_value = "y\n" # Confirm cleanup

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

        # Mock for cat authorized_keys
        mock_stdout_cat = MagicMock()
        mock_stdout_cat.read.return_value = (
            b"ssh-rsa DIFF_UUID_KEY user@host:proxmox1:other-uuid\n"
            b"ssh-rsa SAME_UUID_OLD_KEY user@host:proxmox1:new-uuid\n"
            b"ssh-rsa MANUAL_KEY user@other\n"
        )
        mock_stdout_cat.channel.recv_exit_status.return_value = 0

        mock_stdin_write = MagicMock()
        mock_stdout_write = MagicMock()
        mock_stdout_write.channel.recv_exit_status.return_value = 0

        # Side effect to handle multiple exec_command calls
        mock_ssh.exec_command.side_effect = [
            (MagicMock(), mock_stdout_exists, MagicMock()), # test -d .ssh
            (MagicMock(), mock_stdout_exists, MagicMock()), # test -f auth_keys
            (MagicMock(), mock_stdout_cat, MagicMock()),    # cat auth_keys
            (MagicMock(), MagicMock(), MagicMock()),        # cp (backup)
            (mock_stdin_write, mock_stdout_write, MagicMock()), # cat > auth_keys
        ]

        # Test
        result = ssh_key_manager.connect_and_setup_ssh(
            "host", "user", None, "/local/keys", "/root", "new-uuid", server_name="proxmox1", key_size=3072
        )

        # Assertions
        expected_key = "ssh-rsa BASE64 user@host:proxmox1:new-uuid"

        # Verify backup was called
        calls = [c.args[0] for c in mock_ssh.exec_command.call_args_list]
        self.assertTrue(any("cp /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bak.2023-01-01_10-00-00" in cmd for cmd in calls))

        written_content = mock_stdin_write.write.call_args[0][0]
        self.assertIn("ssh-rsa MANUAL_KEY user@other", written_content)
        self.assertIn(expected_key, written_content)

    @patch('ssh_key_manager.os.path.exists')
    @patch('ssh_key_manager.open', new_callable=mock_open, read_data='{"uuid": "u1", "servers": [{"host": "h1", "enabled": true}, {"host": "h2", "enabled": false}]}')
    @patch('ssh_key_manager.connect_and_setup_ssh')
    @patch('ssh_key_manager.test_connection')
    @patch('ssh_key_manager.disconnect_ssh')
    @patch('ssh_key_manager.sys.exit')
    @patch('ssh_key_manager.sys.argv', ['ssh_key_manager.py'])
    def test_main_config_loading_and_skipping(self, mock_exit, mock_disconnect, mock_test, mock_connect, mock_file, mock_exists):
        mock_exists.return_value = True # config exists

        ssh_key_manager.main()

        self.assertEqual(mock_connect.call_count, 1)
        self.assertEqual(mock_connect.call_args.kwargs['host'], "h1")

    @patch('ssh_key_manager.os.path.exists')
    @patch('ssh_key_manager.open', new_callable=mock_open)
    @patch('ssh_key_manager.sys.exit')
    @patch('ssh_key_manager.sys.argv', ['ssh_key_manager.py'])
    def test_main_first_run(self, mock_exit, mock_file, mock_exists):
        mock_exists.return_value = False # config doesn't exist
        mock_exit.side_effect = SystemExit

        # Capture the data written to the file
        written_contents = []
        mock_file().write.side_effect = written_contents.append

        with self.assertRaises(SystemExit):
            ssh_key_manager.main()

        # Verify template has a UUID
        written_json = "".join(written_contents)
        written_data = json.loads(written_json)
        self.assertIsNotNone(written_data['uuid'])
        mock_exit.assert_called_with(0)

    @patch('ssh_key_manager.paramiko.SSHClient')
    @patch('ssh_key_manager.os.path.exists')
    @patch('ssh_key_manager.open', new_callable=mock_open, read_data='{"uuid": "u1", "servers": [{"name": "S1", "host": "h1", "enabled": true}]}')
    @patch('ssh_key_manager.sys.exit')
    @patch('ssh_key_manager.sys.argv', ['ssh_key_manager.py', '--show'])
    def test_show_mode(self, mock_exit, mock_file, mock_exists, mock_ssh_client):
        mock_exists.side_effect = [True, True] # config exists, key exists
        mock_exit.side_effect = SystemExit

        mock_ssh = MagicMock()
        mock_ssh_client.return_value = mock_ssh

        with self.assertRaises(SystemExit):
            ssh_key_manager.main()

        mock_ssh.connect.assert_called_once()
        mock_exit.assert_called_with(0)

if __name__ == '__main__':
    unittest.main()
