"""
Transport implementation for Circuit Relay v2.

This module implements the transport layer for Circuit Relay v2,
allowing peers to establish connections through relay nodes.
"""

from collections.abc import (
    Awaitable,
)
import logging
from typing import (
    Any,
    Callable,
    Optional,
)

import trio

from libp2p.abc import (
    IHost,
    IListener,
    INetStream,
    ITransport,
)
from libp2p.io.abc import (
    ReadWriteCloser,
)
from libp2p.network.connection.raw_connection import (
    RawConnection,
)
from libp2p.peer.id import (
    ID,
)
from libp2p.peer.peerinfo import (
    PeerInfo,
)
from libp2p.tools.async_service import (
    Service,
)

from .config import (
    ClientConfig,
    RelayConfig,
)
from .dcutr import (
    DCUtRProtocol,
)
from .discovery import (
    RelayDiscovery,
)
from .pb.circuit_pb2 import (
    HopMessage,
)
from .protocol import (
    PROTOCOL_ID,
    CircuitV2Protocol,
)
from .protocol_buffer import (
    OK,
)

logger = logging.getLogger("libp2p.relay.circuit_v2.transport")


class CircuitV2Transport(ITransport):
    """
    CircuitV2Transport implements the transport interface for Circuit Relay v2.

    This transport allows peers to establish connections through relay nodes
    when direct connections are not possible.
    """

    def __init__(
        self,
        host: IHost,
        protocol: CircuitV2Protocol,
        config: RelayConfig,
    ) -> None:
        """
        Initialize the Circuit v2 transport.

        Parameters
        ----------
        host : IHost
            The libp2p host this transport is running on
        protocol : CircuitV2Protocol
            The Circuit v2 protocol instance
        config : RelayConfig
            Relay configuration

        """
        self.host = host
        self.protocol = protocol
        self.config = config
        self.client_config = ClientConfig()
        self.discovery = RelayDiscovery(
            host=host,
            auto_reserve=config.enable_client,
            discovery_interval=config.discovery_interval,
            max_relays=config.max_relays,
        )
        self.dcutr_protocol = None

        # Initialize DCUtR protocol if enabled
        if config.enable_hole_punching:
            self.dcutr_protocol = DCUtRProtocol(host)
            # The protocol will be started by the host later

    async def dial(
        self,
        peer_info: PeerInfo,
        *,
        relay_peer_id: Optional[ID] = None,
        attempt_direct: bool = True,
    ) -> RawConnection:
        """
        Dial a peer through a relay.

        Parameters
        ----------
        peer_info : PeerInfo
            The peer to dial
        relay_peer_id : Optional[ID], optional
            Optional specific relay to use
        attempt_direct : bool, optional
            Whether to attempt a direct connection first, defaults to True

        Returns
        -------
        RawConnection
            The established connection

        Raises
        ------
        ConnectionError
            If the connection cannot be established

        """
        # First try a direct connection if requested
        if attempt_direct:
            try:
                # Attempt direct connection to the peer
                logger.debug("Attempting direct connection to %s", peer_info.peer_id)
                conn = await self.host.get_network().dial_peer(peer_info.peer_id)
                logger.debug("Direct connection to %s succeeded", peer_info.peer_id)
                return conn
            except Exception as e:
                logger.debug(
                    "Direct connection to %s failed, falling back to relay: %s",
                    peer_info.peer_id,
                    str(e),
                )
                # Fall back to relay connection

        # If no specific relay is provided, try to find one
        if relay_peer_id is None:
            relay_peer_id = await self._select_relay(peer_info)
            if not relay_peer_id:
                raise ConnectionError("No suitable relay found")

        # Get a stream to the relay
        relay_stream = await self.host.new_stream(relay_peer_id, [PROTOCOL_ID])
        if not relay_stream:
            raise ConnectionError(f"Could not open stream to relay {relay_peer_id}")

        try:
            # First try to make a reservation if enabled
            if self.config.enable_client:
                success = await self._make_reservation(relay_stream, relay_peer_id)
                if not success:
                    logger.warning(
                        "Failed to make reservation with relay %s", relay_peer_id
                    )

            # Send HOP CONNECT message
            hop_msg = HopMessage(
                type=HopMessage.CONNECT,
                peer=peer_info.peer_id.to_bytes(),
            )
            await relay_stream.write(hop_msg.SerializeToString())

            # Read response
            resp_bytes = await relay_stream.read()
            resp = HopMessage()
            resp.ParseFromString(resp_bytes)

            # Access status attributes directly
            status_code = getattr(resp.status, "code", OK)
            status_msg = getattr(resp.status, "message", "Unknown error")

            if status_code != OK:
                raise ConnectionError(f"Relay connection failed: {status_msg}")

            # Create raw connection from stream
            raw_conn = RawConnection(stream=relay_stream, initiator=True)

            # Schedule hole punching if enabled
            if self.config.enable_hole_punching and self.dcutr_protocol:
                # Schedule hole punching attempt in the background after a short delay
                self._schedule_hole_punch(peer_info.peer_id, relay_peer_id)

            return raw_conn

        except Exception as e:
            await relay_stream.close()
            raise ConnectionError(f"Failed to establish relay connection: {str(e)}")

    def _schedule_hole_punch(self, peer_id: ID, relay_peer_id: ID) -> None:
        """
        Schedule a hole punching attempt in the background.

        Parameters
        ----------
        peer_id : ID
            The peer to attempt hole punching with
        relay_peer_id : ID
            The relay used for the connection
        """
        if not self.dcutr_protocol or not self.config.enable_hole_punching:
            return

        async def attempt_hole_punch() -> None:
            # Wait a short time for the relay connection to be fully established
            await trio.sleep(2.0)

            # Check if we already have a direct connection
            if self.dcutr_protocol._have_direct_connection(peer_id):
                logger.debug(
                    "Already have direct connection to %s, skipping hole punch", peer_id
                )
                return

            # Attempt hole punching
            logger.info(
                "Attempting hole punch with %s via relay %s", peer_id, relay_peer_id
            )
            for i in range(self.config.max_hole_punch_attempts):
                if i > 0:
                    # Wait before retrying
                    await trio.sleep(self.config.hole_punch_retry_interval)

                # Skip if we already have a direct connection
                if self.dcutr_protocol._have_direct_connection(peer_id):
                    logger.debug(
                        "Direct connection established, no need for further hole punching"
                    )
                    return

                # Attempt hole punching
                success = await self.dcutr_protocol.initiate_hole_punch(peer_id)
                if success:
                    logger.info("Hole punching succeeded with %s", peer_id)
                    return

                logger.debug(
                    "Hole punching attempt %d/%d with %s failed",
                    i + 1,
                    self.config.max_hole_punch_attempts,
                    peer_id,
                )

            logger.warning(
                "All hole punching attempts with %s failed, keeping relay connection",
                peer_id,
            )

        # Schedule the hole punching attempt in the background
        nursery = self.host.get_network().nursery
        if nursery:
            nursery.start_soon(attempt_hole_punch)
        else:
            logger.warning("No nursery available, cannot schedule hole punching")

    async def _select_relay(self, peer_info: PeerInfo) -> Optional[ID]:
        """
        Select an appropriate relay for the given peer.

        Parameters
        ----------
        peer_info : PeerInfo
            The peer to connect to

        Returns
        -------
        Optional[ID]
            Selected relay peer ID, or None if no suitable relay found

        """
        # Try to find a relay
        attempts = 0
        while attempts < self.client_config.max_auto_relay_attempts:
            # Get a relay from the list of discovered relays
            relays = self.discovery.get_relays()
            if relays:
                # TODO: Implement more sophisticated relay selection
                # For now, just return the first available relay
                return relays[0]

            # Wait and try discovery
            await trio.sleep(1)
            attempts += 1

        return None

    async def _make_reservation(
        self,
        stream: INetStream,
        relay_peer_id: ID,
    ) -> bool:
        """
        Make a reservation with a relay.

        Parameters
        ----------
        stream : INetStream
            Stream to the relay
        relay_peer_id : ID
            The relay's peer ID

        Returns
        -------
        bool
            True if reservation was successful

        """
        try:
            # Send reservation request
            reserve_msg = HopMessage(
                type=HopMessage.RESERVE,
                peer=self.host.get_id().to_bytes(),
            )
            await stream.write(reserve_msg.SerializeToString())

            # Read response
            resp_bytes = await stream.read()
            resp = HopMessage()
            resp.ParseFromString(resp_bytes)

            # Access status attributes directly
            status_code = getattr(resp.status, "code", OK)
            status_msg = getattr(resp.status, "message", "Unknown error")

            if status_code != OK:
                logger.warning(
                    "Reservation failed with relay %s: %s",
                    relay_peer_id,
                    status_msg,
                )
                return False

            logger.debug("Reservation with relay %s successful", relay_peer_id)
            return True

        except Exception as e:
            logger.error("Error making reservation: %s", str(e))
            return False

    def create_listener(
        self,
        handler_function: Callable[[ReadWriteCloser], Awaitable[None]],
    ) -> IListener:
        """
        Create a listener for the transport.

        Parameters
        ----------
        handler_function : Callable[[ReadWriteCloser], Awaitable[None]]
            Function to handle incoming connections

        Returns
        -------
        IListener
            The created listener
        """
        return CircuitV2Listener(
            host=self.host,
            protocol=self.protocol,
            config=self.config,
            dcutr_protocol=self.dcutr_protocol,
        )


class CircuitV2Listener(Service, IListener):
    """Listener for Circuit Relay v2 connections."""

    def __init__(
        self,
        host: IHost,
        protocol: CircuitV2Protocol,
        config: RelayConfig,
        dcutr_protocol: Optional[DCUtRProtocol] = None,
    ) -> None:
        """
        Initialize the listener.

        Parameters
        ----------
        host : IHost
            The libp2p host
        protocol : CircuitV2Protocol
            The Circuit v2 protocol instance
        config : RelayConfig
            Relay configuration
        dcutr_protocol : Optional[DCUtRProtocol]
            The DCUtR protocol instance for hole punching
        """
        super().__init__()
        self.host = host
        self.protocol = protocol
        self.config = config
        self.dcutr_protocol = dcutr_protocol
        self._handler = None
        self._peer_id = host.get_id()
        self.event_started = trio.Event()

    async def handle_incoming_connection(
        self,
        stream: INetStream,
        remote_peer_id: ID,
    ) -> RawConnection:
        """
        Handle an incoming connection.

        Parameters
        ----------
        stream : INetStream
            The incoming stream
        remote_peer_id : ID
            The remote peer ID

        Returns
        -------
        RawConnection
            Raw connection from the stream
        """
        logger.debug("Received relayed connection from %s", remote_peer_id)

        # Create a raw connection from the stream
        raw_conn = RawConnection(stream=stream, initiator=False)

        # If hole punching is enabled, schedule a hole punch attempt
        if self.config.enable_hole_punching and self.dcutr_protocol:
            # Get the relay peer ID from the stream if possible
            relay_peer_id = None
            try:
                # Attempt to extract relay peer ID from connection or stream metadata
                # This will depend on how the stream info is structured
                pass
            except Exception:
                pass

            # Schedule hole punching in the background
            if relay_peer_id:
                self._schedule_hole_punch(remote_peer_id, relay_peer_id)
            else:
                # If we can't determine the relay, still try hole punching
                self._schedule_hole_punch(remote_peer_id, None)

        return raw_conn

    def _schedule_hole_punch(self, peer_id: ID, relay_peer_id: Optional[ID]) -> None:
        """
        Schedule a hole punching attempt in the background.

        Parameters
        ----------
        peer_id : ID
            The peer to attempt hole punching with
        relay_peer_id : Optional[ID]
            The relay used for the connection (if known)
        """
        if not self.dcutr_protocol or not self.config.enable_hole_punching:
            return

        async def attempt_hole_punch() -> None:
            # Wait a short time for the relay connection to be fully established
            await trio.sleep(2.0)

            # Check if we already have a direct connection
            if self.dcutr_protocol._have_direct_connection(peer_id):
                logger.debug(
                    "Already have direct connection to %s, skipping hole punch", peer_id
                )
                return

            # Attempt hole punching
            relay_info = f" via relay {relay_peer_id}" if relay_peer_id else ""
            logger.info("Attempting hole punch with %s%s", peer_id, relay_info)

            for i in range(self.config.max_hole_punch_attempts):
                if i > 0:
                    # Wait before retrying
                    await trio.sleep(self.config.hole_punch_retry_interval)

                # Skip if we already have a direct connection
                if self.dcutr_protocol._have_direct_connection(peer_id):
                    logger.debug(
                        "Direct connection established, no need for further hole punching"
                    )
                    return

                # Attempt hole punching
                success = await self.dcutr_protocol.initiate_hole_punch(peer_id)
                if success:
                    logger.info("Hole punching succeeded with %s", peer_id)
                    return

                logger.debug(
                    "Hole punching attempt %d/%d with %s failed",
                    i + 1,
                    self.config.max_hole_punch_attempts,
                    peer_id,
                )

            logger.warning(
                "All hole punching attempts with %s failed, keeping relay connection",
                peer_id,
            )

        # Schedule the hole punching attempt in the background
        nursery = self.host.get_network().nursery
        if nursery:
            nursery.start_soon(attempt_hole_punch)
        else:
            logger.warning("No nursery available, cannot schedule hole punching")

    async def run(self) -> None:
        """Run the listener."""
        self.event_started.set()
        await self.manager.wait_finished()

    async def listen(self, maddr: Any, nursery: Any) -> bool:
        """
        Start listening on the given multiaddr.

        Parameters
        ----------
        maddr : Any
            The multiaddr to listen on
        nursery : Any
            The nursery to run in

        Returns
        -------
        bool
            True if listening succeeded
        """
        # For relay listener, we don't actually bind to an address
        # We just need to register with the protocol to receive connections
        logger.debug("Relay listener started")

        # Start the DCUtR protocol if available
        if self.config.enable_hole_punching and self.dcutr_protocol:
            logger.debug("Starting DCUtR protocol for hole punching")
            nursery.start_soon(self.dcutr_protocol.run)

        return True

    def get_addrs(self) -> tuple[Any, ...]:
        """
        Get the multiaddrs the listener is listening on.

        Returns
        -------
        tuple[Any, ...]
            Tuple of multiaddrs
        """
        # For relay listener, we don't actually have addresses
        return tuple()

    async def close(self) -> None:
        """Close the listener."""
        logger.debug("Closing relay listener")

        # Stop the DCUtR protocol if it's running
        if self.dcutr_protocol:
            await self.dcutr_protocol.stop()

        # Stop this listener service
        await self.stop()
