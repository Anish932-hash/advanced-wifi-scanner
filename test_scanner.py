#!/usr/bin/env python3
"""
Test Script for Advanced WiFi Scanner
This script performs basic functionality tests without requiring root privileges
"""

import os
import sys
import json
import subprocess
from unittest.mock import patch, MagicMock
import tempfile

# Add current directory to path to import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from advanced_wifi_scanner import WiFiNetwork, WiFiScanner
    from wifi_utils import WiFiInterface, NetworkAnalyzer, ReportGenerator, WordlistManager
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all required files are in the same directory")
    sys.exit(1)

class WiFiScannerTester:
    """Test class for WiFi Scanner functionality"""
    
    def __init__(self):
        self.test_results = []
        self.temp_dir = tempfile.mkdtemp()
        print(f"Using temporary directory: {self.temp_dir}")
    
    def log_test(self, test_name: str, passed: bool, message: str = ""):
        """Log test results"""
        status = "PASS" if passed else "FAIL"
        self.test_results.append({
            'test': test_name,
            'status': status,
            'message': message
        })
        print(f"[{status}] {test_name}: {message}")
    
    def test_wifi_network_creation(self):
        """Test WiFiNetwork data class"""
        try:
            network = WiFiNetwork(
                bssid="AA:BB:CC:DD:EE:FF",
                essid="TestNetwork",
                channel=6,
                power=-50,
                encryption="WPA2",
                cipher="CCMP",
                authentication="PSK"
            )
            
            assert network.bssid == "AA:BB:CC:DD:EE:FF"
            assert network.essid == "TestNetwork"
            assert network.channel == 6
            assert network.power == -50
            assert network.clients == []
            assert network.attempts == 0
            
            self.log_test("WiFiNetwork Creation", True, "All attributes set correctly")
            
        except Exception as e:
            self.log_test("WiFiNetwork Creation", False, str(e))
    
    def test_config_loading(self):
        """Test configuration file loading"""
        try:
            config_file = "config.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                # Check required sections
                required_sections = ['scanner_settings', 'output_settings', 'scanning_tools']
                for section in required_sections:
                    assert section in config, f"Missing section: {section}"
                
                self.log_test("Config Loading", True, "Configuration file loaded successfully")
            else:
                self.log_test("Config Loading", False, "config.json not found")
                
        except Exception as e:
            self.log_test("Config Loading", False, str(e))
    
    def test_wifi_interface_detection(self):
        """Test WiFi interface detection (mock)"""
        try:
            wifi_interface = WiFiInterface()
            
            # Mock the interface detection
            with patch('subprocess.run') as mock_run:
                mock_run.return_value.stdout = "wlan0     IEEE 802.11  ESSID:off/any"
                mock_run.return_value.returncode = 0
                
                interfaces = wifi_interface.get_wireless_interfaces()
                
                self.log_test("WiFi Interface Detection", True, f"Mock detected interfaces: {interfaces}")
                
        except Exception as e:
            self.log_test("WiFi Interface Detection", False, str(e))
    
    def test_network_analyzer(self):
        """Test network analysis functions"""
        try:
            analyzer = NetworkAnalyzer()
            
            # Test signal strength analysis
            strength = analyzer.analyze_signal_strength(-60)
            assert strength in ["Excellent", "Very Good", "Good", "Fair", "Weak", "Very Weak"]
            
            # Test distance estimation
            distance = analyzer.estimate_distance(-60)
            assert isinstance(distance, float) and distance > 0
            
            # Test encryption analysis
            encryption_analysis = analyzer.analyze_encryption("WPA2")
            assert 'security_level' in encryption_analysis
            assert 'vulnerabilities' in encryption_analysis
            
            self.log_test("Network Analyzer", True, "All analysis functions working")
            
        except Exception as e:
            self.log_test("Network Analyzer", False, str(e))
    
    def test_report_generation(self):
        """Test report generation"""
        try:
            report_gen = ReportGenerator(self.temp_dir)
            
            # Create test network data
            test_networks = [
                {
                    'essid': 'TestNetwork1',
                    'bssid': 'AA:BB:CC:DD:EE:FF',
                    'channel': 6,
                    'power': -50,
                    'encryption': 'WPA2',
                    'wps': False,
                    'handshake_captured': False,
                    'attempts': 1,
                    'last_seen': '2024-01-03 14:25:30'
                },
                {
                    'essid': 'TestNetwork2',
                    'bssid': 'BB:CC:DD:EE:FF:AA',
                    'channel': 11,
                    'power': -70,
                    'encryption': 'WPA',
                    'wps': True,
                    'handshake_captured': True,
                    'attempts': 2,
                    'last_seen': '2024-01-03 14:26:30'
                }
            ]
            
            # Test CSV report
            csv_file = report_gen.generate_csv_report(test_networks)
            csv_success = os.path.exists(csv_file) if csv_file else False
            
            # Test XML report
            xml_file = report_gen.generate_xml_report(test_networks)
            xml_success = os.path.exists(xml_file) if xml_file else False
            
            # Test Markdown report
            md_file = report_gen.generate_markdown_report(test_networks)
            md_success = os.path.exists(md_file) if md_file else False
            
            success_count = sum([csv_success, xml_success, md_success])
            self.log_test("Report Generation", success_count >= 2, 
                         f"Generated {success_count}/3 report formats successfully")
            
        except Exception as e:
            self.log_test("Report Generation", False, str(e))
    
    def test_wordlist_manager(self):
        """Test wordlist management"""
        try:
            wordlist_mgr = WordlistManager(self.temp_dir)
            
            # Test custom wordlist creation
            wordlist_file = wordlist_mgr.create_custom_wordlist("TestNetwork", "AA:BB:CC:DD:EE:FF")
            
            if wordlist_file and os.path.exists(wordlist_file):
                with open(wordlist_file, 'r') as f:
                    lines = f.readlines()
                
                # Check if wordlist has content
                assert len(lines) > 0, "Wordlist is empty"
                
                # Check if network name variations are included
                content = ''.join(lines)
                assert 'TestNetwork' in content or 'testnetwork' in content
                
                self.log_test("Wordlist Manager", True, f"Created wordlist with {len(lines)} entries")
            else:
                self.log_test("Wordlist Manager", False, "Failed to create wordlist file")
                
        except Exception as e:
            self.log_test("Wordlist Manager", False, str(e))
    
    def test_scanner_initialization(self):
        """Test WiFi scanner initialization"""
        try:
            # Test with mock interface
            scanner = WiFiScanner(interface="wlan0", output_dir=self.temp_dir)
            
            # Check basic attributes
            assert scanner.interface == "wlan0"
            assert scanner.monitor_interface == "wlan0mon"
            assert scanner.output_dir == self.temp_dir
            assert scanner.max_attempts == 3
            assert scanner.networks == {}
            
            # Check if output directory was created
            assert os.path.exists(self.temp_dir)
            
            self.log_test("Scanner Initialization", True, "Scanner initialized with correct parameters")
            
        except Exception as e:
            self.log_test("Scanner Initialization", False, str(e))
    
    def test_command_execution_mock(self):
        """Test command execution with mocking"""
        try:
            scanner = WiFiScanner(interface="wlan0", output_dir=self.temp_dir)
            
            # Mock successful command
            with patch('subprocess.Popen') as mock_popen:
                mock_process = MagicMock()
                mock_process.communicate.return_value = ("success output", "")
                mock_process.returncode = 0
                mock_popen.return_value = mock_process
                
                success, stdout, stderr = scanner.run_command("echo test")
                
                assert success == True
                assert "success output" in stdout
                
            self.log_test("Command Execution Mock", True, "Command execution working correctly")
            
        except Exception as e:
            self.log_test("Command Execution Mock", False, str(e))
    
    def test_dependency_check_mock(self):
        """Test dependency checking with mocking"""
        try:
            scanner = WiFiScanner(interface="wlan0", output_dir=self.temp_dir)
            
            # Mock successful dependency check
            with patch.object(scanner, 'run_command') as mock_run:
                mock_run.return_value = (True, "/usr/bin/aircrack-ng", "")
                
                result = scanner.check_dependencies()
                
                # Should return True if all dependencies are found
                self.log_test("Dependency Check Mock", True, "Dependency check completed")
                
        except Exception as e:
            self.log_test("Dependency Check Mock", False, str(e))
    
    def test_csv_parsing_mock(self):
        """Test CSV parsing with mock data"""
        try:
            scanner = WiFiScanner(interface="wlan0", output_dir=self.temp_dir)
            
            # Create mock CSV file
            mock_csv_content = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2024-01-03 14:25:30, 2024-01-03 14:26:30, 6, 54, WPA2, CCMP, PSK, -50, 10, 0, 0.0.0.0, 11, TestNetwork,
BB:CC:DD:EE:FF:AA, 2024-01-03 14:25:30, 2024-01-03 14:26:30, 11, 54, WPA, TKIP, PSK, -70, 5, 0, 0.0.0.0, 12, TestNetwork2,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
"""
            
            # Write mock CSV file
            mock_csv_file = os.path.join(self.temp_dir, "test_airodump.csv")
            with open(mock_csv_file, 'w') as f:
                f.write(mock_csv_content)
            
            # Test parsing
            networks = scanner.parse_airodump_csv(mock_csv_file)
            
            assert len(networks) >= 1, "Should parse at least one network"
            
            if networks:
                network = networks[0]
                assert network.bssid == "AA:BB:CC:DD:EE:FF"
                assert network.essid == "TestNetwork"
                assert network.channel == 6
                assert network.power == -50
            
            self.log_test("CSV Parsing Mock", True, f"Parsed {len(networks)} networks from mock CSV")
            
        except Exception as e:
            self.log_test("CSV Parsing Mock", False, str(e))
    
    def run_all_tests(self):
        """Run all tests"""
        print("=" * 60)
        print("Advanced WiFi Scanner - Test Suite")
        print("=" * 60)
        
        test_methods = [
            self.test_wifi_network_creation,
            self.test_config_loading,
            self.test_wifi_interface_detection,
            self.test_network_analyzer,
            self.test_report_generation,
            self.test_wordlist_manager,
            self.test_scanner_initialization,
            self.test_command_execution_mock,
            self.test_dependency_check_mock,
            self.test_csv_parsing_mock
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                test_name = test_method.__name__.replace('test_', '').replace('_', ' ').title()
                self.log_test(test_name, False, f"Unexpected error: {e}")
        
        # Print summary
        print("\n" + "=" * 60)
        print("Test Summary")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results if result['status'] == 'PASS')
        total = len(self.test_results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("\n🎉 All tests passed! The scanner is ready for use.")
        else:
            print(f"\n⚠️  {total - passed} test(s) failed. Check the issues above.")
        
        # Cleanup
        try:
            import shutil
            shutil.rmtree(self.temp_dir)
            print(f"\nCleaned up temporary directory: {self.temp_dir}")
        except:
            pass
        
        return passed == total

def main():
    """Main test function"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Advanced WiFi Scanner Test Suite")
        print("Usage: python3 test_scanner.py")
        print("\nThis script tests the WiFi scanner functionality without requiring root privileges.")
        print("It uses mocking to simulate system calls and network operations.")
        return
    
    tester = WiFiScannerTester()
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()