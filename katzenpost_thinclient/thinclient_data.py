from dataclasses import dataclass

@dataclass
class ReadChannelReply:
    """read_channel() response"""
    message_id: bytes
    channel_id: int
    envelope_hash: bytes
    envelope_descriptor: bytes
    send_message_payload: bytes
