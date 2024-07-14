import asyncio
import discoverhosts
import getipaddr
import rendertopo

async def main():
    try:
        # network = input("Enter the network (e.g., 192.168.1.0/24): ")
        ipaddr = getipaddr.get_wifi_ip()
        await discoverhosts.DiscoverHosts.scan_network(str(ipaddr))
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        rendertopo.main()
        print("Scan complete.")

if __name__ == "__main__":
        asyncio.run(main())
        