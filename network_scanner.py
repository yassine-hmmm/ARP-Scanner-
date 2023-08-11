import scapy.all as scapy
import argparse
import pyfiglet
import colorama



def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v","--verbose", help='increase output verbosity', action="store_true")
    parser.add_argument("-n","--network", help="network to scan eg: 192.168.1.0/24", required=True)
    return parser.parse_args()

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    ether_broadcast= scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    frame = ether_broadcast / arp_request
    results = scapy.srp(frame, timeout=1, verbose=False)[0]
    return  results


def scan_summary(results):
    colorama.init()
    green = colorama.Fore.GREEN
    yellow = colorama.Fore.YELLOW
    red = colorama.Fore.RED
    blue = colorama.Fore.BLUE
    figlet = pyfiglet.Figlet(font='letters')
    counter = 0
    print(blue + figlet.renderText('SCANNER') )
    print('-' * 60)
    print('Index' +'\t\t'+'IP Address' +'\t\t'+ 'Mac Address')
    print(red + '-' * 60)
    for element in results:
        print(str(counter), green + element[1].psrc, yellow + element[1].hwsrc, sep='\t\t')
        print(red + '-' * 60)
        counter+=1


class Scanner:


    def __init__(self,network):
        self.network = network
        results = self.scan()
        self.scan_summary(results=results)





    def scan(self):
        arp_request = scapy.ARP(pdst=self.network)
        ether_broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        frame = ether_broadcast / arp_request
        results = scapy.srp(frame,timeout=1,verbose=False)[0]
        return  results

    def scan_summary(self, results):
        colorama.init()
        green = colorama.Fore.GREEN
        yellow = colorama.Fore.YELLOW
        red = colorama.Fore.RED
        blue = colorama.Fore.BLUE
        figlet = pyfiglet.Figlet(font='letters')
        counter = 0
        print(blue + figlet.renderText('SCANNER'))
        print('-' * 60)
        print('Index' + '\t\t' + 'IP Address' + '\t\t' + 'Mac Address')
        print(red + '-' * 60)
        for element in results:
            print(str(counter), green + element[1].psrc, yellow + element[1].hwsrc, sep='\t\t')
            print(red + '-' * 60)
            counter += 1


if __name__ == "__main__":
    args = get_arguments()
    '''results = scan(ip=args.network)
    scan_summary(results)'''
    scn = Scanner(network=args.network)


