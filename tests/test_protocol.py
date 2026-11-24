import io,struct,unittest
from harbor.protocol import Frame,Opcode,ProtocolError,encode_frame,recv_frame,HEADER,MAX_PAYLOAD

class Wire:
    def __init__(self,data):self.data=io.BytesIO(data)
    def recv(self,n):return self.data.read(min(n,3))

class ProtocolTests(unittest.TestCase):
    def test_binary_frame_survives_partial_reads(self):
        f=Frame(Opcode.UPLOAD_CHUNK,7,{'offset':123},b'\x00hello\xff')
        wire=encode_frame(f);self.assertEqual(len(wire),20+len(b'{"offset":123}')+7)
        got=recv_frame(Wire(wire));self.assertEqual((got.opcode,got.request_id,got.metadata,got.payload),(Opcode.UPLOAD_CHUNK,7,{'offset':123},b'\x00hello\xff'))
    def test_length_rejected_before_body_read(self):
        with self.assertRaises(ProtocolError):recv_frame(Wire(HEADER.pack(b'HBR1',1,1,0,1,0,MAX_PAYLOAD+1)))
    def test_truncated_frame_rejected(self):
        with self.assertRaises(ProtocolError):recv_frame(Wire(encode_frame(Frame(Opcode.PING,1,{}))[:-1]))
    def test_duplicate_json_keys_rejected(self):
        data=b'{"x":1,"x":2}'
        with self.assertRaises(ProtocolError):recv_frame(Wire(HEADER.pack(b'HBR1',1,1,0,1,len(data),0)+data))
