"""
NetScan - Network scanning tool main application.

This module serves as the entry point for the NetScan application,
orchestrating network discovery, host scanning, and topology rendering.
"""
import asyncio
import argparse
import sys
import discoverhosts
import getipaddr
import rendertopo
import config


async def scan_network(network=None, config_obj=None):
    """
    Run the network scan.

    Args:
        network (str, optional): Network to scan in CIDR notation
        config_obj (Config, optional): Configuration object

    Returns:
        bool: True if scan completed successfully, False otherwise
    """
    try:
        if not network:
            network = getipaddr.get_wifi_ip()
            if not network:
                print("Failed to detect network. Please check your network connection.")
                print("You can specify a network manually using the --network option.")
                return False

        print(f"\n{'='*60}")
        print("NetScan - Network Scanner")
        print(f"{'='*60}")
        print(f"Target Network: {network}")
        print(f"{'='*60}\n")

        await discoverhosts.DiscoverHosts.scan_network(str(network))
        return True
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="NetScan - Advanced Network Scanning Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan local network (auto-detected)
  python app.py

  # Scan specific network
  python app.py --network 192.168.1.0/24

  # Use custom configuration
  python app.py --config myconfig.json

  # Skip topology visualization
  python app.py --no-topology

  # Create default configuration file
  python app.py --create-config
        """
    )

    parser.add_argument(
        '--network', '-n',
        type=str,
        help='Network to scan in CIDR notation (e.g., 192.168.1.0/24)'
    )

    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to configuration file'
    )

    parser.add_argument(
        '--no-topology', '-nt',
        action='store_true',
        help='Skip network topology visualization'
    )

    parser.add_argument(
        '--create-config',
        action='store_true',
        help='Create a default configuration file and exit'
    )

    parser.add_argument(
        '--version', '-v',
        action='version',
        version='NetScan 1.0.0'
    )

    return parser.parse_args()


async def main():
    """
    Main asynchronous function to run the network scan.

    Discovers the local network, scans all hosts, and renders the topology.
    """
    args = parse_arguments()

    # Handle create-config option
    if args.create_config:
        config.create_default_config()
        return

    # Load configuration
    config_obj = config.Config(args.config) if args.config else config.Config()

    # Run the scan
    success = await scan_network(args.network, config_obj)

    # Render topology if requested and scan was successful
    if success and not args.no_topology:
        try:
            print("\nGenerating network topology visualization...")
            rendertopo.main()
        except Exception as e:
            print(f"Error rendering topology: {e}")

    print("\nScan complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
