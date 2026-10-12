"""Bounded DNS and ordinary TLS termination inside the isolated lab VM."""
import asyncio
import ipaddress
import json
from pathlib import Path
import ssl
import struct

ROOT = Path('/home/lab/.local/state/android-release-network')


def dns_reply(data, records):
    if not 12 <= len(data) <= 512:
        return None
    ident, flags, questions, answers, authority, additional = struct.unpack('!6H', data[:12])
    if flags & 0xf800 or questions != 1 or answers or authority:
        return None
    cursor, labels = 12, []
    while cursor < len(data):
        length = data[cursor]
        cursor += 1
        if length == 0:
            break
        if length > 63 or cursor + length > len(data) or len(labels) >= 127:
            return None
        try:
            labels.append(data[cursor:cursor + length].decode('ascii').lower())
        except UnicodeDecodeError:
            return None
        cursor += length
    else:
        return None
    if cursor + 4 > len(data) or cursor - 12 > 255:
        return None
    kind, klass = struct.unpack('!HH', data[cursor:cursor + 4])
    question = data[12:cursor + 4]
    address = records.get('.'.join(labels))
    payload = b''
    if address and klass == 1 and kind == 1:
        payload = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + ipaddress.IPv4Address(address).packed
    header = struct.pack('!6H', ident, 0x8400 | (flags & 0x0100) | (0 if address else 3),
                         1, int(bool(payload)), 0, 0)
    return header + question + payload


class Dns(asyncio.DatagramProtocol):
    def __init__(self, records):
        self.records = records

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        response = dns_reply(data, self.records)
        if response is not None:
            self.transport.sendto(response, address)


async def main():
    settings = json.loads((ROOT / 'settings.json').read_text())
    records = {settings['provider']: settings['guest_ip']}
    records.update({f'r{i + 1}.relays.gchat.boo': address for i, address in enumerate(settings['relay_ips'])})
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(ROOT / 'tls/provider.crt', ROOT / 'tls/provider.key')
    active = 0

    async def proxy(reader, writer):
        nonlocal active
        if active >= 16:
            writer.close()
            return
        active += 1
        upstream = None
        try:
            peer = writer.get_extra_info('peername')[0]
            address = ipaddress.IPv4Address(peer)
            if address.is_loopback:
                source = peer
            elif address in ipaddress.IPv4Network('10.244.0.0/16'):
                octets = address.packed
                source = f'127.91.{octets[2]}.{octets[3]}'
            else:
                raise ValueError('unexpected isolated provider client address')
            remote, upstream = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', 18080, local_addr=(source, 0)), 5)

            async def copy(source, destination):
                while data := await asyncio.wait_for(source.read(65536), 45):
                    destination.write(data)
                    await asyncio.wait_for(destination.drain(), 15)

            tasks = [asyncio.create_task(copy(reader, upstream)), asyncio.create_task(copy(remote, writer))]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, TimeoutError, ValueError):
            pass
        finally:
            if upstream is not None:
                upstream.close()
            writer.close()
            active -= 1

    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: Dns(records), local_addr=('0.0.0.0', 5353))
    server = await asyncio.start_server(proxy, '0.0.0.0', 443, ssl=context, ssl_handshake_timeout=5)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
