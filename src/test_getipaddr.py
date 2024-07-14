import unittest
from unittest.mock import patch

from getipaddr import get_wifi_ip

class TestGetWifiIP(unittest.TestCase):

    @patch('getipaddr.get_local_ip')
    def test_get_wifi_ip_success(self, mock_get_local_ip):
        mock_get_local_ip.return_value = '192.168.0.100'
        expected_result = '192.168.0.0/24'
        
        result = get_wifi_ip()
        
        self.assertEqual(result, expected_result)
        mock_get_local_ip.assert_called_once_with('wi-fi')

    @patch('getipaddr.get_local_ip')
    def test_get_wifi_ip_exception(self, mock_get_local_ip):
        mock_get_local_ip.side_effect = Exception('Some error')
        
        result = get_wifi_ip()
        
        self.assertIsNone(result)
        mock_get_local_ip.assert_called_once_with('wi-fi')

if __name__ == '__main__':
    unittest.main()