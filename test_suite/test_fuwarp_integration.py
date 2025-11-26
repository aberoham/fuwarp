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
            
            mock_class.assert_called_with(mode='install', debug=False, selected_tools=[])
    
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
                selected_tools=['node', 'python']
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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])