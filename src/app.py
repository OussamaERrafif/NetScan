import discoverhosts

def main():
    try:
        # network = input("Enter the network (e.g., 192.168.1.0/24): ")
        discoverhosts.DiscoverHosts.scan_network("192.168.1.112/24")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
