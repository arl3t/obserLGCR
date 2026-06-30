"""Validación de redes privadas: RFC 1918 (IPv4) + ULA RFC 4193 (IPv6 fc00::/7)."""

import ipaddress
from ipaddress import IPv4Network, IPv6Network

RFC1918_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

ULA_V6 = ipaddress.ip_network("fc00::/7")


def is_private_network(network: IPv4Network | IPv6Network) -> bool:
    if network.version == 4:
        return any(network.subnet_of(rfc) for rfc in RFC1918_V4)
    return network.subnet_of(ULA_V6) or network.is_private


def is_rfc1918_network(network: IPv4Network | IPv6Network) -> bool:
    return is_private_network(network)


def parse_cidr(value: str) -> IPv4Network | IPv6Network:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"CIDR inválido: {value}") from exc


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"Dirección IP inválida: {value}") from exc


def ip_in_network(ip_str: str, cidr: str) -> bool:
    network = parse_cidr(cidr)
    ip = parse_ip(ip_str)
    if ip not in network:
        return False
    if network.version == 4 and network.prefixlen <= 30:
        if ip == network.network_address or ip == network.broadcast_address:
            return False
    return True


def host_capacity(network: IPv4Network | IPv6Network) -> int:
    if network.version == 4:
        if network.prefixlen >= 31:
            return network.num_addresses
        return max(network.num_addresses - 2, 0)
    if network.prefixlen >= 127:
        return network.num_addresses
    return max(network.num_addresses - 2, 0)


def iter_ips_in_range(start_ip: str, end_ip: str) -> list[str]:
    start = parse_ip(start_ip)
    end = parse_ip(end_ip)
    if start.version != end.version:
        raise ValueError("Rango IP: versiones distintas")
    if int(start) > int(end):
        raise ValueError("start_ip debe ser <= end_ip")
    if int(end) - int(start) > 512:
        raise ValueError("Rango máximo 512 direcciones por operación bulk")
    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]


OCCUPIED_STATUSES = frozenset({"Online", "Reserved", "DHCP"})
