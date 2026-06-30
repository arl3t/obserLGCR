from app.models.ipam import IPAMAddress
from app.schemas.subnet import IPAddressResponse


def to_address_response(address: IPAMAddress) -> IPAddressResponse:
    return IPAddressResponse(
        id=address.id,
        subnet_id=address.subnet_id,
        ip_address=str(address.ip_address),
        status=address.status,
        hostname=address.hostname,
        mac_address=str(address.mac_address) if address.mac_address else None,
        description=address.description,
        last_seen=address.last_seen,
        is_discovered_by_nmap=address.is_discovered_by_nmap,
        expires_at=address.expires_at,
        noc_device_id=str(address.noc_device_id) if address.noc_device_id else None,
        dhcp_lease_expires=address.dhcp_lease_expires,
        updated_at=address.updated_at,
        reservation_expired=False,
    )
