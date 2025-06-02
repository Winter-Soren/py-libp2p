"""
Direct Connection Upgrade through Relay (DCUtR) protocol implementation.

This module implements the DCUtR protocol as specified in:
https://github.com/libp2p/specs/blob/master/relay/DCUtR.md

DCUtR enables peers behind NAT to establish direct connections
using hole punching techniques.
"""

import logging
import time
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

import trio
from multiaddr import Multiaddr

from libp2p.abc import (
    IHost,
    INetStream,
)
from libp2p.custom_types import (
    TProtocol,
)
from libp2p.network.connection.raw_connection import (
    RawConnection,
)
from libp2p.peer.id import (
    ID,
)
from libp2p.tools.async_service import (
    Service,
)

from .nat import (
    ReachabilityChecker,
)
from .pb.dcutr_pb2 import (
    HolePunch,
)

logger = logging.getLogger("libp2p.relay.circuit_v2.dcutr")

# Protocol ID for DCUtR
PROTOCOL_ID = TProtocol("/libp2p/dcutr")

# Timeout constants
DIAL_TIMEOUT = 15  # seconds
SYNC_TIMEOUT = 5  # seconds
HOLE_PUNCH_TIMEOUT = 30  # seconds

# Maximum observed addresses to exchange
MAX_OBSERVED_ADDRS = 20

# Maximum message size (4KiB as per spec)
MAX_MESSAGE_SIZE = 4 * 1024


class DCUtRProtocol(Service):
    """
    DCUtRProtocol implements the Direct Connection Upgrade through Relay protocol.

    This protocol allows two NATed peers to establish direct connections through
    hole punching, after they have established an initial connection through a relay.
    """

    def __init__(self, host: IHost):
        """
        Initialize the DCUtR protocol.

        Parameters
        ----------
        host : IHost
            The libp2p host this protocol is running on
        """
        super().__init__()
        self.host = host
        self.event_started = trio.Event()
        self._hole_punch_attempts: Dict[ID, int] = {}
        self._direct_connections: Set[ID] = set()
        self._in_progress: Set[ID] = set()
        self._reachability_checker = ReachabilityChecker(host)

    async def run(self, *, task_status: Any = trio.TASK_STATUS_IGNORED) -> None:
        """Run the protocol service."""
        try:
            # Register protocol handler
            logger.debug("Registering stream handler for DCUtR protocol")
            self.host.set_stream_handler(PROTOCOL_ID, self._handle_dcutr_stream)
            logger.debug("Stream handler registered successfully")

            # Signal that we're ready
            self.event_started.set()
            task_status.started()
            logger.debug("DCUtR protocol service started")

            # Wait for service to be stopped
            await self.manager.wait_finished()

        finally:
            # Try to unregister protocol handler on shutdown
            try:
                self.host.remove_stream_handler(PROTOCOL_ID)
            except Exception as e:
                logger.error("Error unregistering stream handler: %s", str(e))

    async def _handle_dcutr_stream(self, stream: INetStream) -> None:
        """
        Handle incoming DCUtR streams.

        Parameters
        ----------
        stream : INetStream
            The incoming stream
        """
        remote_peer_id = stream.get_remote_peer_id()
        logger.debug("Received DCUtR stream from peer %s", remote_peer_id)

        try:
            # Add peer to in-progress set to prevent multiple simultaneous attempts
            if remote_peer_id in self._in_progress:
                logger.debug("Already have an active hole punch with %s", remote_peer_id)
                await stream.close()
                return

            self._in_progress.add(remote_peer_id)

            # Check if we already have a direct connection
            if await self._have_direct_connection(remote_peer_id):
                logger.debug("Already have direct connection to %s", remote_peer_id)
                await stream.close()
                self._in_progress.remove(remote_peer_id)
                return

            # Read the initial CONNECT message
            msg_bytes = await stream.read()
            if not msg_bytes or len(msg_bytes) > MAX_MESSAGE_SIZE:
                logger.error("Invalid message size: %d", len(msg_bytes or b""))
                await stream.close()
                self._in_progress.remove(remote_peer_id)
                return

            msg = HolePunch()
            try:
                msg.ParseFromString(msg_bytes)
            except Exception as e:
                logger.error("Failed to parse message: %s", str(e))
                await stream.close()
                self._in_progress.remove(remote_peer_id)
                return

            # Handle CONNECT message
            if msg.type != HolePunch.CONNECT:
                logger.error("Expected CONNECT message, got %s", msg.type)
                await stream.close()
                self._in_progress.remove(remote_peer_id)
                return

            # Get observed addresses
            remote_addrs = self._decode_observed_addrs(msg.ObsAddrs)
            logger.debug(
                "Received %d observed addresses from peer %s",
                len(remote_addrs),
                remote_peer_id,
            )

            # Start RTT measurement and send our CONNECT message
            start_time = time.time()
            local_addrs = await self._get_observed_addrs()
            connect_msg = HolePunch(
                type=HolePunch.CONNECT,
                ObsAddrs=local_addrs,
            )
            await stream.write(connect_msg.SerializeToString())

            # Wait for SYNC message
            sync_bytes = await stream.read()
            if not sync_bytes or len(sync_bytes) > MAX_MESSAGE_SIZE:
                logger.error("Invalid SYNC message size: %d", len(sync_bytes or b""))
                await stream.close()
                self._in_progress.remove(remote_peer_id)
                return

            sync_msg = HolePunch()
            try:
                sync_msg.ParseFromString(sync_bytes)
            except Exception as e:
                logger.error("Failed to parse SYNC message: %s", str(e))
                await stream.close()
                self._in_progress.remove(remote_peer_id)
                return

            if sync_msg.type != HolePunch.SYNC:
                logger.error("Expected SYNC message, got %s", sync_msg.type)
                await stream.close()
                self._in_progress.remove(remote_peer_id)
                return

            # Calculate RTT
            rtt = time.time() - start_time
            logger.debug("Measured RTT: %.3f seconds", rtt)

            # Immediately initiate outbound connections
            async with trio.open_nursery() as nursery:
                for addr in remote_addrs:
                    nursery.start_soon(self._dial_peer, remote_peer_id, addr)

            # Result will be determined by the dial attempts
            await stream.close()
            self._in_progress.remove(remote_peer_id)

        except Exception as e:
            logger.error("Error handling DCUtR stream: %s", str(e))
            await stream.close()
            if remote_peer_id in self._in_progress:
                self._in_progress.remove(remote_peer_id)

    async def initiate_hole_punch(self, peer_id: ID) -> bool:
        """
        Initiate a hole punch with a peer.

        Parameters
        ----------
        peer_id : ID
            The peer to hole punch with

        Returns
        -------
        bool
            True if hole punching succeeded
        """
        logger.debug("Initiating hole punch with peer %s", peer_id)

        # Check if we already have a direct connection
        if await self._have_direct_connection(peer_id):
            logger.debug("Already have direct connection to %s", peer_id)
            return True

        # Check if we're already attempting a hole punch
        if peer_id in self._in_progress:
            logger.debug("Already have an active hole punch with %s", peer_id)
            return False

        # Check reachability - if peer is public, we can just dial directly
        is_peer_public = await self._reachability_checker.check_peer_reachability(peer_id)
        if is_peer_public:
            logger.debug("Peer %s appears to be publicly reachable, attempting direct dial", peer_id)
            try:
                # Try a direct dial first
                await self.host.get_network().dial_peer(peer_id)
                logger.info("Direct connection to %s succeeded without hole punching", peer_id)
                return True
            except Exception as e:
                logger.debug(
                    "Direct dial to public peer %s failed, falling back to hole punching: %s",
                    peer_id,
                    str(e)
                )
                # Continue with hole punching as fallback

        # Track this attempt
        self._in_progress.add(peer_id)
        self._hole_punch_attempts[peer_id] = self._hole_punch_attempts.get(peer_id, 0) + 1

        try:
            # Open a DCUtR stream to the peer
            stream = await self.host.new_stream(peer_id, [PROTOCOL_ID])
            if not stream:
                logger.error("Failed to open DCUtR stream to %s", peer_id)
                self._in_progress.remove(peer_id)
                return False

            # Send CONNECT message with our observed addresses
            local_addrs = await self._get_observed_addrs()
            connect_msg = HolePunch(
                type=HolePunch.CONNECT,
                ObsAddrs=local_addrs,
            )
            await stream.write(connect_msg.SerializeToString())

            # Wait for CONNECT response
            start_time = time.time()
            connect_resp_bytes = await stream.read()
            if not connect_resp_bytes or len(connect_resp_bytes) > MAX_MESSAGE_SIZE:
                logger.error(
                    "Invalid CONNECT response size: %d", len(connect_resp_bytes or b"")
                )
                await stream.close()
                self._in_progress.remove(peer_id)
                return False

            connect_resp = HolePunch()
            try:
                connect_resp.ParseFromString(connect_resp_bytes)
            except Exception as e:
                logger.error("Failed to parse CONNECT response: %s", str(e))
                await stream.close()
                self._in_progress.remove(peer_id)
                return False

            if connect_resp.type != HolePunch.CONNECT:
                logger.error(
                    "Expected CONNECT response, got %s", connect_resp.type
                )
                await stream.close()
                self._in_progress.remove(peer_id)
                return False

            # Calculate RTT for synchronization
            rtt = time.time() - start_time
            logger.debug("Measured RTT: %.3f seconds", rtt)

            # Send SYNC message to trigger hole punching
            sync_msg = HolePunch(
                type=HolePunch.SYNC,
            )
            await stream.write(sync_msg.SerializeToString())

            # Parse remote addresses
            remote_addrs = self._decode_observed_addrs(connect_resp.ObsAddrs)
            logger.debug(
                "Received %d observed addresses from peer %s",
                len(remote_addrs),
                peer_id,
            )

            # Wait for half the RTT to synchronize the connection attempts
            await trio.sleep(rtt / 2)

            # Attempt to establish direct connections
            async with trio.open_nursery() as nursery:
                for addr in remote_addrs:
                    nursery.start_soon(self._dial_peer, peer_id, addr)

            # Close the DCUtR stream - direct connection result will be determined separately
            await stream.close()
            self._in_progress.remove(peer_id)

            # Wait a bit and check if we have established a direct connection
            await trio.sleep(1.0)
            if await self._have_direct_connection(peer_id):
                logger.info("Successfully established direct connection to %s", peer_id)
                return True
            else:
                logger.warning("Failed to establish direct connection to %s", peer_id)
                return False

        except Exception as e:
            logger.error("Error initiating hole punch: %s", str(e))
            if peer_id in self._in_progress:
                self._in_progress.remove(peer_id)
            return False

    async def _dial_peer(self, peer_id: ID, addr: Multiaddr) -> None:
        """
        Attempt to dial a peer at a specific address.

        Parameters
        ----------
        peer_id : ID
            The peer to dial
        addr : Multiaddr
            The address to dial
        """
        logger.debug("Attempting to dial %s at %s", peer_id, addr)

        try:
            # Check if this is a viable address for hole punching
            if "/p2p-circuit" in str(addr):
                logger.debug("Skipping relay address for hole punching: %s", addr)
                return
                
            # Check if this is a private address that won't work for public dialing
            if not self._reachability_checker.is_addr_public(addr):
                logger.debug("Skipping private address for hole punching: %s", addr)
                return

            with trio.fail_after(DIAL_TIMEOUT):
                # Add peer ID to the address if not already present
                addr_str = str(addr)
                if not f"/p2p/{peer_id}" in addr_str:
                    addr_with_peer = Multiaddr(f"{addr_str}/p2p/{peer_id}")
                else:
                    addr_with_peer = addr
                
                # Use the host's dial function to attempt the connection
                await self.host.connect(addr_with_peer)
                
                # If we got here, the connection was successful
                logger.info("Successfully established direct connection to %s at %s", peer_id, addr)
                self._direct_connections.add(peer_id)
        except trio.TooSlowError:
            logger.debug("Dial to %s at %s timed out", peer_id, addr)
        except Exception as e:
            logger.debug("Failed to dial %s at %s: %s", peer_id, addr, str(e))

    async def _have_direct_connection(self, peer_id: ID) -> bool:
        """
        Check if we have a direct connection to a peer.

        Parameters
        ----------
        peer_id : ID
            The peer to check

        Returns
        -------
        bool
            True if we have a direct connection
        """
        # First check our tracked direct connections
        if peer_id in self._direct_connections:
            return True

        # Then check with the host
        conns = self.host.get_network().connections.get(peer_id, [])
        for conn in conns:
            # Check if this is a relay connection or direct
            if not any(str(addr).startswith("/p2p-circuit") for addr in conn.get_transport_addresses()):
                self._direct_connections.add(peer_id)
                return True
        
        return False

    async def _get_observed_addrs(self) -> List[bytes]:
        """
        Get the observed addresses of this node.

        Returns
        -------
        List[bytes]
            List of multiaddrs encoded as bytes
        """
        addrs = []
        
        # Get addresses from the host's address manager
        # Filter out relay addresses and convert to bytes
        for addr in self.host.get_addrs():
            # Skip relay addresses for hole punching
            if "/p2p-circuit" in str(addr):
                continue
            addrs.append(addr.to_bytes())
        
        # Use reachability checker to prioritize public addresses if available
        is_public, public_addrs = await self._reachability_checker.check_self_reachability()
        if is_public and public_addrs:
            # Prioritize public addresses by putting them first
            public_addr_bytes = [addr.to_bytes() for addr in public_addrs]
            private_addr_bytes = [addr_b for addr_b in addrs if addr_b not in public_addr_bytes]
            addrs = public_addr_bytes + private_addr_bytes
            
        # Limit to maximum number of addresses
        return addrs[:MAX_OBSERVED_ADDRS]

    def _decode_observed_addrs(self, addr_bytes: List[bytes]) -> List[Multiaddr]:
        """
        Decode observed addresses from bytes.

        Parameters
        ----------
        addr_bytes : List[bytes]
            List of multiaddrs encoded as bytes

        Returns
        -------
        List[Multiaddr]
            List of decoded multiaddrs
        """
        addrs = []
        for addr_b in addr_bytes:
            try:
                addr = Multiaddr(addr_b)
                addrs.append(addr)
            except Exception as e:
                logger.error("Failed to decode multiaddr: %s", str(e))
                
        # Use reachability checker to prioritize public addresses
        public_addrs = self._reachability_checker.get_public_addrs(addrs)
        private_addrs = [addr for addr in addrs if addr not in public_addrs]
        
        # Return public addresses first for better hole punching chances
        return public_addrs + private_addrs 