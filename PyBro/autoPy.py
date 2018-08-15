# Signature ProtoType
'''
signature protosig_bittorrent_tracker {
  	
  	# tcp payload or udp payload
  	ip-proto == tcp
  	
  	payload
  	
  	tcp-state responder or originator
  	
  	requires-reverse-signature protosig_

  	eval ProtoSig::match
}
'''

# Error Class
class MyError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

# Signature Class
class proto_sig:

    # Constructor
    def __init__(self, name=None, ip_proto=None, payload=None, tcp_state=None,
                 req_rev_sig=None, eval=None):
        self.name = '' if name is None else name
        self.ip_proto = 'tcp' if ip_proto is None else ip_proto
        self.payload = [] if payload is None else payload
        self.tcp_state = 'originator' if tcp_state is None else tcp_state
        self.req_rev_sig = None if req_rev_sig is None else req_rev_sig
        self.eval = 'eval ProtoSig::match' if eval is None else eval

    def make_sig(self):

        t_ip_proto_table = ['tcp', 't', 'TCP']
        u_ip_proto_table = ['udp', 'u', 'UDP']
        o_tcp_state_table = ['originator', 'Originator', 'O', 'o', 'orig', 'ori']
        r_tcp_state_table = ['responder', 'Responder', 'R', 'r', 'resp', 'res']

        try:

            # name
            text = input('signature의 이름을 입력해주세요 : ')
            self.name = text

            # ip proto
            text = input('UDP 페이로드 or TCP 페이로드 : ')

            if text in t_ip_proto_table:
                self.ip_proto = 'tcp'
            elif text in u_ip_proto_table:
                self.ip_proto = 'udp'
            else:
                self.ip_proto = 'tcp'
                raise MyError("Example : udp, tcp, u, t (udp / tcp 두 개만 호환됩니다)")

            # payload
            while(1):
                print("페이로드는 다중 입력 가능합니다(종료 : 1 입력)")
                text = input('페이로드를 flex reg-exp 방식으로 쓰시오 : ')

                if text == '1':
                    break

                text = '(|.*[\\r\\n])' + text
                self.payload.append(text)
            
            # ip proto
            text = input('Originator or Responder : ')

            if text in o_tcp_state_table:
                self.tcp_state = 'originator'
            elif text in r_tcp_state_table:
                self.tcp_state = 'responder'
            else:
                self.tcp_state = 'originator'
                raise MyError("Example : orig, originator, responder, resp, r")


        except BaseException as e:
            print(e)

    def print_sig(self):
        print("protosig_" + self.name)
        print("ip-proto == " + self.ip_proto)
        for i in self.payload:
            print("payload /" + i + "/")
        print("tcp-state " + self.tcp_state)
        print(self.eval)
