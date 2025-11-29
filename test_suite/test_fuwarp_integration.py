"""
Integration tests for fuwarp.py

These tests verify the core workflows and functionality of the fuwarp script
by mocking external dependencies and testing realistic scenarios.
"""
import sys
from unittest.mock import patch, MagicMock, call
import pytest

# Import test utilities
from helpers import (
    MockBuilder, mock_fuwarp_environment, assert_subprocess_called_with,
    assert_file_written, FuwarpTestCase
)
import mock_data

# Import the fuwarp module
import fuwarp


class TestCertificateManagement(FuwarpTestCase):
    """Tests for certificate download and validation."""
    
    def test_certificate_download_success(self):
        """Test successful certificate download from warp-cli."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_tools('openssl')
            .build())
        
        with mock_fuwarp_environment(mock_config) as mocks:
            instance = self.create_fuwarp_instance(mode='install')
            result = instance.download_certificate()
            
            assert result is True
            assert_subprocess_called_with(mocks['subprocess'], ['warp-cli', 'certs'])
    
    def test_certificate_download_warp_not_installed(self):
        """Test certificate download when WARP is not installed."""
        mock_config = MockBuilder().with_warp_not_installed().build()
        
        with mock_fuwarp_environment(mock_config):
            instance = self.create_fuwarp_instance(mode='install')
            result = instance.download_certificate()
            
            assert result is False
    
    def test_certificate_validation_success(self):
        """Test certificate validation with openssl."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_tools('openssl')
            .with_subprocess_response(returncode=0)  # openssl verify success
            .build())
        
        with mock_fuwarp_environment(mock_config) as mocks:
            instance = self.create_fuwarp_instance()
            # Trigger certificate validation through status check
            instance.check_all_status()
            
            # The actual command uses x509 -checkend, not just verify
            assert_subprocess_called_with(mocks['subprocess'], ['openssl', 'x509', '-noout', '-checkend'])
    
    def test_certificate_already_exists_check(self):
        """Test behavior when certificate already exists and is valid."""
        mock_config = (MockBuilder()
            .with_certificate()
            .with_warp_connected()
            .with_tools('openssl')
            .with_subprocess_response(returncode=0)  # openssl check shows valid
            .build())
        
        with mock_fuwarp_environment(mock_config) as mocks:
            instance = self.create_fuwarp_instance()
            instance.check_all_status()
            
            # Should check existing certificate validity
            assert mocks['exists'].called


class TestToolSetup(FuwarpTestCase):
    """Tests for individual tool certificate setup."""
    
    @pytest.mark.parametrize("tool,check_commands", [
        ("node", [["npm", "config", "get", "cafile"]]),
        ("python", [["python3", "-m", "pip", "--version"]]),
        ("java", [["java", "-version"]]),
    ])
    def test_tool_availability_check(self, tool, check_commands):
        """Test that tools are properly checked for availability."""
        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool(tool)
            .build())
        
        # Add appropriate responses for each tool
        for _ in check_commands:
            mock_config['subprocess_side_effect'].append(MagicMock(returncode=0, stdout=""))
        
        with mock_fuwarp_environment(mock_config) as mocks:
            instance = self.create_fuwarp_instance()
            setup_method = getattr(instance, f"setup_{tool}_cert")
            setup_method()
            
            assert mocks['which'].called
            assert any(call(tool) in mocks['which'].call_args_list for call in [call])
    
    def test_node_npm_setup_workflow(self):
        """Test complete Node.js/npm certificate setup."""
        mock_config = (MockBuilder()
            .with_certificate()
            .with_tools('node', 'npm')
            .with_env_var('HOME', mock_data.HOME_DIR)
            .with_subprocess_response(stdout=mock_data.NPM_CONFIG_CAFILE_NULL)  # npm config get
            .with_subprocess_response(returncode=0)  # npm config set
            .build())
        
        with mock_fuwarp_environment(mock_config) as mocks:
            # Mock input to auto-answer 'Y' and Path.touch
            with patch('builtins.input', return_value='Y'), \
                 patch('pathlib.Path.touch'):
                instance = self.create_fuwarp_instance(mode='install')
                instance.setup_node_cert()
            
            # Should check npm config
            assert_subprocess_called_with(mocks['subprocess'], ['npm', 'config', 'get', 'cafile'])
    
    def test_python_requests_setup(self):
        """Test Python requests/urllib3 certificate setup."""
        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool('python3')
            .with_subprocess_response(stdout=mock_data.PYTHON_VERSION)  # python version
            .with_subprocess_response(returncode=1)  # pip not found
            .build())
        
        with mock_fuwarp_environment(mock_config) as mocks:
            instance = self.create_fuwarp_instance(mode='status')
            instance.setup_python_cert()
            
            # Python should have been checked
            assert mocks['which'].called
            assert any(call('python3') in mocks['which'].call_args_list for call in [call])


class TestCLIAndWorkflow(FuwarpTestCase):
    """Tests for CLI argument parsing and complete workflows."""
    
    @patch('fuwarp.sys.argv', ['fuwarp.py', '--fix'])
    def test_cli_fix_mode(self):
        """Test --fix argument sets install mode."""
        with patch('fuwarp.FuwarpPython') as mock_class:
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance
            
            with patch('fuwarp.sys.exit'):
                fuwarp.main()
            
            mock_class.assert_called_with(
                mode='install', debug=False, selected_tools=[],
                cert_file=None, manual_cert=False, skip_verify=False
            )
    
    @patch('fuwarp.sys.argv', ['fuwarp.py', '--tools', 'node,python'])
    def test_cli_tool_selection(self):
        """Test --tools argument parsing."""
        with patch('fuwarp.FuwarpPython') as mock_class:
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance
            
            with patch('fuwarp.sys.exit'):
                fuwarp.main()
            
            mock_class.assert_called_with(
                mode='status',
                debug=False,
                selected_tools=['node', 'python'],
                cert_file=None, manual_cert=False, skip_verify=False
            )
    
    def test_complete_status_workflow(self):
        """Test complete status check workflow with multiple tools."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_certificate()
            .with_tools('node', 'npm', 'python3', 'keytool', 'openssl')
            .with_subprocess_response(stdout=mock_data.NPM_CONFIG_CAFILE_SET)  # npm config get
            .with_subprocess_response(stdout=mock_data.NODE_VERSION)  # node version  
            .with_subprocess_response(stdout=mock_data.PYTHON_VERSION)  # python version
            .with_subprocess_response(returncode=1)  # pip not found
            .with_subprocess_response(stdout="keytool 11.0.17")  # keytool exists
            .with_subprocess_response(returncode=0)  # openssl validity check
            .build())
        
        with mock_fuwarp_environment(mock_config) as mocks:
            instance = self.create_fuwarp_instance()
            # Run the complete status check
            instance.check_all_status()
            
            # Should have checked for various tools
            assert mocks['which'].called
            # Check that npm config was queried
            assert_subprocess_called_with(mocks['subprocess'], ['npm', 'config', 'get'])
            # Check that keytool was found
            assert any(call('keytool') in mocks['which'].call_args_list for call in [call])


class TestToolSelection(FuwarpTestCase):
    """Tests for tool selection and filtering logic."""
    
    def test_tool_selection_by_key(self):
        """Test selecting tools by their key names."""
        instance = self.create_fuwarp_instance(selected_tools=['node', 'python'])
        
        assert instance.should_process_tool('node') is True
        assert instance.should_process_tool('python') is True
        assert instance.should_process_tool('java') is False
    
    def test_tool_selection_by_tag(self):
        """Test selecting tools by their tags."""
        instance = self.create_fuwarp_instance(selected_tools=['nodejs', 'pip'])
        
        # Should match by tag
        assert instance.should_process_tool('node') is True  # 'nodejs' tag
        assert instance.should_process_tool('python') is True  # 'pip' tag
        assert instance.should_process_tool('java') is False
    
    def test_tool_selection_validation(self):
        """Test validation of selected tools."""
        instance = self.create_fuwarp_instance(
            selected_tools=['node', 'invalid-tool', 'python']
        )
        
        invalid_tools = instance.validate_selected_tools()
        assert 'invalid-tool' in invalid_tools
        assert 'node' not in invalid_tools


class TestErrorScenarios(FuwarpTestCase):
    """Tests for error handling and edge cases."""
    
    def test_certificate_download_network_error(self):
        """Test handling of network errors during certificate download."""
        mock_config = (MockBuilder()
            .with_tools('warp-cli', 'openssl')
            .with_subprocess_response(
                returncode=1, 
                stderr=mock_data.NETWORK_ERROR
            )
            .build())
        
        with mock_fuwarp_environment(mock_config):
            instance = self.create_fuwarp_instance(mode='install')
            result = instance.download_certificate()
            
            assert result is False
    
    def test_permission_denied_writing_certificate(self):
        """Test handling of permission errors when writing certificates."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_tools('openssl')
            .build())
        
        with mock_fuwarp_environment(mock_config):
            with patch('fuwarp.shutil.copy') as mock_copy:
                mock_copy.side_effect = PermissionError(mock_data.PERMISSION_DENIED_ERROR)
                
                instance = self.create_fuwarp_instance(mode='install')
                # The download_certificate method doesn't catch PermissionError
                # so we expect it to raise
                with pytest.raises(PermissionError):
                    instance.download_certificate()
    
    def test_malformed_certificate_handling(self):
        """Test handling of malformed certificates from warp-cli."""
        mock_config = (MockBuilder()
            .with_tools('warp-cli', 'openssl')
            .with_subprocess_response(
                returncode=0,
                stdout=mock_data.MOCK_INVALID_CERTIFICATE
            )
            .with_subprocess_response(
                returncode=1,  # openssl verify fails
                stderr=mock_data.OPENSSL_VERIFY_FAILURE
            )
            .build())
        
        with mock_fuwarp_environment(mock_config):
            instance = self.create_fuwarp_instance(mode='install')
            result = instance.download_certificate()
            
            assert result is False
    
    def test_tool_not_found_graceful_handling(self):
        """Test graceful handling when tools are not found."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_certificate()
            .build())  # No tools configured except warp
        
        with mock_fuwarp_environment(mock_config) as mocks:
            instance = self.create_fuwarp_instance(mode='status')
            # Run status check - should handle missing tools gracefully
            instance.check_all_status()
            
            # Should have tried to check for various tools
            assert mocks['which'].called
            # Should have completed without errors despite missing tools
            assert True  # If we get here, no exceptions were raised


class TestConnectionVerification(FuwarpTestCase):
    """Tests for network connection verification."""
    
    @patch('fuwarp.urllib.request.urlopen')
    def test_python_connection_verification_success(self, mock_urlopen):
        """Test successful Python HTTPS connection verification."""
        mock_response = MagicMock()
        mock_response.code = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        instance = self.create_fuwarp_instance()
        result = instance.verify_connection('python')
        
        assert result == "WORKING"
        mock_urlopen.assert_called_once()
    
    def test_node_connection_verification_success(self):
        """Test successful Node.js HTTPS connection verification."""
        mock_config = (MockBuilder()
            .with_tool('node')
            .with_subprocess_response(
                returncode=0,
                stderr="HTTP Status: 200"
            )
            .build())
        
        with mock_fuwarp_environment(mock_config):
            instance = self.create_fuwarp_instance()
            result = instance.verify_connection('node')
            
            assert result == "WORKING"
    
    def test_connection_verification_failure(self):
        """Test failed connection verification."""
        mock_config = (MockBuilder()
            .with_tool('wget')
            .with_subprocess_response(
                returncode=1,
                stderr="Unable to establish SSL connection"
            )
            .build())
        
        with mock_fuwarp_environment(mock_config):
            instance = self.create_fuwarp_instance()
            result = instance.verify_connection('wget')
            
            assert result == "FAILED"


class TestPlatformSpecific(FuwarpTestCase):
    """Tests for platform-specific behavior."""

    @pytest.mark.parametrize("platform,expected_path", [
        ("Darwin", "/Library/Java/JavaVirtualMachines"),
        ("Linux", "/usr/lib/jvm"),
    ])
    def test_platform_specific_paths(self, platform, expected_path):
        """Test that platform-specific paths are used correctly."""
        with patch('platform.system', return_value=platform):
            instance = fuwarp.FuwarpPython(mode='status')

            # Check that instance is aware of platform
            # This would need actual implementation testing
            assert True  # Placeholder for actual platform-specific tests


class TestStatusFunctionContracts(FuwarpTestCase):
    """Contract tests for all check_*_status() functions.

    These tests verify that all status check functions return a boolean value,
    preventing bugs like issue #20 where a function forgot to return has_issues.
    """

    def get_all_status_methods(self, instance):
        """Discover all check_*_status methods via introspection.

        Excludes check_all_status() which is the orchestrator method.
        """
        return [
            name for name in dir(instance)
            if name.startswith('check_') and name.endswith('_status')
            and name != 'check_all_status'  # Exclude orchestrator
            and callable(getattr(instance, name))
        ]

    def test_all_status_functions_return_boolean(self, tmp_path):
        """Ensure all check_*_status() functions return a boolean (not None).

        Regression test for issue #20 - prevents forgetting return statements.
        This test automatically discovers all check_*_status methods and verifies
        each returns a proper boolean value.
        """
        # Create a temporary cert file for the status checks
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fuwarp.FuwarpPython(mode='status')

        status_methods = self.get_all_status_methods(instance)

        # Verify we found the expected methods (sanity check)
        assert len(status_methods) >= 10, f"Expected at least 10 status methods, found {len(status_methods)}: {status_methods}"

        # Expected methods based on the codebase
        expected_methods = [
            'check_git_status', 'check_node_status', 'check_python_status',
            'check_gcloud_status', 'check_java_status', 'check_jenv_status',
            'check_gradle_status', 'check_dbeaver_status', 'check_wget_status',
            'check_podman_status', 'check_rancher_status', 'check_android_status',
            'check_colima_status'
        ]
        for expected in expected_methods:
            assert expected in status_methods, f"Expected method {expected} not found"

        # Test each status method
        failed_methods = []
        for method_name in status_methods:
            method = getattr(instance, method_name)

            # Mock all external dependencies so functions hit early returns
            with patch.object(instance, 'command_exists', return_value=False), \
                 patch.object(instance, 'get_jenv_java_homes', return_value=[]), \
                 patch('os.path.exists', return_value=False):

                result = method(str(cert_file))

                if result is None:
                    failed_methods.append(f"{method_name} returned None")
                elif not isinstance(result, bool):
                    failed_methods.append(f"{method_name} returned {type(result).__name__}, not bool")

        assert not failed_methods, "Status function contract violations:\n" + "\n".join(failed_methods)

    def test_status_functions_return_false_when_tool_not_installed(self, tmp_path):
        """Verify status functions return False (no issues) when tool is not installed."""
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fuwarp.FuwarpPython(mode='status')

        status_methods = self.get_all_status_methods(instance)

        for method_name in status_methods:
            method = getattr(instance, method_name)

            # Mock tool as not installed
            with patch.object(instance, 'command_exists', return_value=False), \
                 patch.object(instance, 'get_jenv_java_homes', return_value=[]), \
                 patch('os.path.exists', return_value=False):

                result = method(str(cert_file))

                # When tool is not installed, there should be no issues to report
                assert result is False, f"{method_name} should return False when tool not installed, got {result}"

    def test_check_jenv_status_returns_boolean_with_java_homes(self, tmp_path):
        """Verify check_jenv_status returns boolean when jenv has Java installations.

        Regression test for issue #20 - the bug only manifests when jenv has
        Java homes because empty java_homes triggers an early return.
        """
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fuwarp.FuwarpPython(mode='status')

        # Mock jenv having Java installations
        fake_java_homes = ['/fake/java/home/17', '/fake/java/home/11']

        # Mock keytool as available but certificate check fails
        mock_keytool_result = MagicMock()
        mock_keytool_result.returncode = 1
        mock_keytool_result.stdout = b''

        with patch.object(instance, 'get_jenv_java_homes', return_value=fake_java_homes), \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch('subprocess.run', return_value=mock_keytool_result):

            result = instance.check_jenv_status(str(cert_file))

            assert result is not None, "check_jenv_status returned None instead of bool"
            assert isinstance(result, bool), f"check_jenv_status returned {type(result).__name__}, not bool"


class TestCertificateAppending(FuwarpTestCase):
    """Tests for certificate appending to ensure proper PEM formatting (issue #13)."""

    def test_append_to_bundle_without_trailing_newline(self, tmp_path):
        """Ensure appending to a bundle without newline doesn't corrupt PEM.

        This tests the fix for issue #13 where appending to a file without
        a trailing newline would produce malformed PEM like:
        -----END CERTIFICATE----------BEGIN CERTIFICATE-----
        """
        # Create a CA bundle file WITHOUT trailing newline
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE_NO_NEWLINE)

        # Create a certificate file to append
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Create instance and call safe_append_certificate
        with patch('platform.system', return_value='Darwin'):
            instance = fuwarp.FuwarpPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        # Read the resulting file
        content = bundle_file.read_text()

        # Verify that -----END CERTIFICATE----- is followed by newline, not -----BEGIN
        # This pattern should NOT appear in a valid PEM file
        assert "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" not in content

        # Verify proper separation exists
        assert "-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----" in content or \
               "-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----" in content

    def test_append_to_bundle_with_trailing_newline(self, tmp_path):
        """Verify normal case still works - bundle with trailing newline."""
        # Create a CA bundle file WITH trailing newline
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE)  # Has trailing newline

        # Create a certificate file to append
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Create instance and call safe_append_certificate
        with patch('platform.system', return_value='Darwin'):
            instance = fuwarp.FuwarpPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        # Read the resulting file
        content = bundle_file.read_text()

        # Verify that the malformed pattern doesn't exist
        assert "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" not in content

    def test_append_ensures_certificate_ends_with_newline(self, tmp_path):
        """Ensure appended certificate itself ends with newline."""
        # Create an empty bundle file
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text("")

        # Create a certificate file WITHOUT trailing newline
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE_NO_NEWLINE)

        # Create instance and call safe_append_certificate
        with patch('platform.system', return_value='Darwin'):
            instance = fuwarp.FuwarpPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        # Read the resulting file
        content = bundle_file.read_text()

        # Verify the file ends with a newline
        assert content.endswith('\n')

    def test_append_skips_if_certificate_already_exists(self, tmp_path):
        """Verify that appending skips if certificate already exists in bundle."""
        # Create a bundle that already contains the certificate
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Use the same certificate file
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        original_size = bundle_file.stat().st_size

        # Create instance and mock certificate_exists_in_file to return True
        # (since mock certificates don't work with openssl fingerprint check)
        with patch('platform.system', return_value='Darwin'):
            instance = fuwarp.FuwarpPython(mode='install')
            with patch.object(instance, 'certificate_exists_in_file', return_value=True):
                result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        # Should return True (success, even though skipped)
        assert result is True

        # File size should be the same (nothing appended)
        assert bundle_file.stat().st_size == original_size

    def test_append_to_nonexistent_target_creates_file(self, tmp_path):
        """Verify appending to a non-existent file creates it with the certificate."""
        # Target file doesn't exist
        bundle_file = tmp_path / "new-bundle.pem"

        # Create a certificate file
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Create instance and call safe_append_certificate
        with patch('platform.system', return_value='Darwin'):
            instance = fuwarp.FuwarpPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        # File should now exist
        assert bundle_file.exists()

        # Content should be the certificate
        content = bundle_file.read_text()
        assert "-----BEGIN CERTIFICATE-----" in content
        assert "-----END CERTIFICATE-----" in content


class TestCodeQuality:
    """Static analysis tests to catch unsafe patterns in the codebase."""

    def test_no_unsafe_certificate_appends_in_fuwarp(self):
        """Ensure fuwarp.py uses safe_append_certificate() for all certificate appends.

        Regression test for issue #21 - prevents adding new unsafe certificate
        appends that could produce malformed PEM files.

        Unsafe patterns detected:
        - Direct file opens with 'a' mode for certificate/bundle files
        - Writing certificate content without using safe_append_certificate()
        """
        import os
        import re

        # Read the source file
        test_dir = os.path.dirname(os.path.abspath(__file__))
        fuwarp_path = os.path.join(os.path.dirname(test_dir), "fuwarp.py")

        with open(fuwarp_path, 'r') as f:
            source = f.read()

        # Pattern 1: Direct append mode opens for bundle/cert files
        # This catches: with open(some_bundle, 'a') as f:
        unsafe_append_pattern = re.compile(
            r"with\s+open\s*\([^)]*(?:bundle|cert|ca)[^)]*['\"]a['\"]\s*\)\s*as",
            re.IGNORECASE
        )

        matches = unsafe_append_pattern.findall(source)
        assert not matches, (
            f"Found unsafe certificate append patterns in fuwarp.py:\n"
            f"{matches}\n\n"
            f"Use self.safe_append_certificate(cert_path, target_path) instead"
        )

        # Pattern 2: Direct f.write() of certificate content to append
        # This catches patterns like: f.write(cf.read()) where cf is a cert file
        unsafe_write_pattern = re.compile(
            r"f\.write\s*\(\s*(?:cf|cert_file|CERT).*\.read\s*\(\s*\)\s*\)"
        )

        matches = unsafe_write_pattern.findall(source)
        assert not matches, (
            f"Found unsafe certificate write patterns in fuwarp.py:\n"
            f"{matches}\n\n"
            f"Use self.safe_append_certificate(cert_path, target_path) instead"
        )

    def test_no_unsafe_certificate_appends_in_fuwarp_windows(self):
        """Ensure fuwarp_windows.py uses append_certificate_if_missing() for all appends.

        Same as test_no_unsafe_certificate_appends_in_fuwarp but for Windows port.
        """
        import os
        import re

        # Read the source file
        test_dir = os.path.dirname(os.path.abspath(__file__))
        fuwarp_windows_path = os.path.join(os.path.dirname(test_dir), "fuwarp_windows.py")

        with open(fuwarp_windows_path, 'r') as f:
            source = f.read()

        # Pattern 1: Direct append mode opens for bundle/cert files
        # Exclude the append_certificate_if_missing implementation itself
        lines = source.split('\n')
        in_append_method = False
        unsafe_lines = []

        for i, line in enumerate(lines, 1):
            # Track when we're inside append_certificate_if_missing
            if 'def append_certificate_if_missing' in line:
                in_append_method = True
            elif in_append_method and line.strip().startswith('def '):
                in_append_method = False

            # Skip the implementation of the safe method
            if in_append_method:
                continue

            # Check for unsafe patterns
            if re.search(r"with\s+open\s*\([^)]*['\"]a['\"]\s*\)", line, re.IGNORECASE):
                if 'bundle' in line.lower() or 'cert' in line.lower() or 'ca' in line.lower():
                    unsafe_lines.append(f"Line {i}: {line.strip()}")

        assert not unsafe_lines, (
            f"Found unsafe certificate append patterns in fuwarp_windows.py:\n"
            + "\n".join(unsafe_lines) + "\n\n"
            f"Use self.append_certificate_if_missing(cert_path, target_path) instead"
        )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])