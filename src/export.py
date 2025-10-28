"""
Export module for scan results.

This module provides functionality to export scan results to various formats
including JSON, CSV, and XML.
"""
import json
import csv
import xml.etree.ElementTree as ET
from xml.dom import minidom


def export_to_json(results, filename="scan_results.json"):
    """
    Export scan results to JSON format.

    Args:
        results (list): List of scan results
        filename (str): Output filename

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Results exported to {filename}")
        return True
    except Exception as e:
        print(f"Error exporting to JSON: {e}")
        return False


def export_to_csv(results, filename="scan_results.csv"):
    """
    Export scan results to CSV format.

    Args:
        results (list): List of scan results
        filename (str): Output filename

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(filename, 'w', newline='') as f:
            if not results:
                return False

            # Define CSV headers
            headers = ['IP', 'MAC', 'Hostname', 'State', 'Ports', 'Services', 'OS']
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

            # Write each host
            for host in results:
                row = {
                    'IP': host.get('ip', 'N/A'),
                    'MAC': host.get('mac', 'N/A'),
                    'Hostname': '',
                    'State': '',
                    'Ports': '',
                    'Services': '',
                    'OS': ''
                }

                # Extract hostname and state
                services = host.get('services', {})
                if services:
                    for ip, info in services.items():
                        row['Hostname'] = info.get('hostname', 'N/A')
                        row['State'] = info.get('state', 'N/A')

                        # Extract ports and services
                        protocols = info.get('protocols', {})
                        ports = []
                        service_names = []
                        for proto, proto_info in protocols.items():
                            for service in proto_info.get('services', []):
                                ports.append(str(service.get('port', '')))
                                service_names.append(service.get('name', ''))

                        row['Ports'] = ', '.join(ports)
                        row['Services'] = ', '.join(service_names)

                # Extract OS information
                os_info = host.get('os', [])
                if os_info and isinstance(os_info, list):
                    os_classes = os_info[0].get('os_classes', [])
                    if os_classes and isinstance(os_classes, list):
                        if isinstance(os_classes[0], dict):
                            row['OS'] = f"{os_classes[0].get('vendor', '')} " \
                                       f"{os_classes[0].get('osfamily', '')}"

                writer.writerow(row)

        print(f"Results exported to {filename}")
        return True
    except Exception as e:
        print(f"Error exporting to CSV: {e}")
        return False


def export_to_xml(results, filename="scan_results.xml"):
    """
    Export scan results to XML format.

    Args:
        results (list): List of scan results
        filename (str): Output filename

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        root = ET.Element('scan_results')

        for host in results:
            host_elem = ET.SubElement(root, 'host')

            # Add IP and MAC
            ET.SubElement(host_elem, 'ip').text = host.get('ip', 'N/A')
            ET.SubElement(host_elem, 'mac').text = host.get('mac', 'N/A')

            # Add services
            services = host.get('services', {})
            services_elem = ET.SubElement(host_elem, 'services')
            for ip, info in services.items():
                service_elem = ET.SubElement(services_elem, 'service')
                ET.SubElement(service_elem, 'hostname').text = info.get('hostname', 'N/A')
                ET.SubElement(service_elem, 'state').text = info.get('state', 'N/A')

                # Add protocols
                protocols = info.get('protocols', {})
                protocols_elem = ET.SubElement(service_elem, 'protocols')
                for proto, proto_info in protocols.items():
                    proto_elem = ET.SubElement(protocols_elem, 'protocol', name=proto)
                    for service in proto_info.get('services', []):
                        port_elem = ET.SubElement(proto_elem, 'port')
                        ET.SubElement(port_elem, 'number').text = str(service.get('port', ''))
                        ET.SubElement(port_elem, 'name').text = service.get('name', '')
                        ET.SubElement(port_elem, 'version').text = service.get('version', '')

            # Add OS information
            os_info = host.get('os', [])
            os_elem = ET.SubElement(host_elem, 'os')
            if os_info and isinstance(os_info, list):
                for os_data in os_info:
                    os_classes = os_data.get('os_classes', [])
                    if os_classes and isinstance(os_classes, list):
                        for os_class in os_classes:
                            if isinstance(os_class, dict):
                                class_elem = ET.SubElement(os_elem, 'osclass')
                                ET.SubElement(class_elem, 'vendor').text = os_class.get('vendor', '')
                                ET.SubElement(class_elem, 'osfamily').text = \
                                    os_class.get('osfamily', '')
                                ET.SubElement(class_elem, 'accuracy').text = \
                                    str(os_class.get('accuracy', ''))

            # Add traceroute
            traceroute = host.get('traceroute', [])
            trace_elem = ET.SubElement(host_elem, 'traceroute')
            for hop in traceroute:
                ET.SubElement(trace_elem, 'hop').text = hop

        # Pretty print XML
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        with open(filename, 'w') as f:
            f.write(xml_str)

        print(f"Results exported to {filename}")
        return True
    except Exception as e:
        print(f"Error exporting to XML: {e}")
        return False


def export_results(results, format='json', filename=None):
    """
    Export scan results to specified format.

    Args:
        results (list): List of scan results
        format (str): Export format ('json', 'csv', or 'xml')
        filename (str, optional): Output filename

    Returns:
        bool: True if successful, False otherwise
    """
    if not filename:
        filename = f"scan_results.{format}"

    if format.lower() == 'json':
        return export_to_json(results, filename)
    elif format.lower() == 'csv':
        return export_to_csv(results, filename)
    elif format.lower() == 'xml':
        return export_to_xml(results, filename)
    else:
        print(f"Unsupported format: {format}")
        return False
