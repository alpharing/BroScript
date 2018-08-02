signature protosig_bittorrent_tracker_client {
  	ip-proto == tcp
  	payload /^.*\/announce\?.*info_hash/
  	tcp-state originator
}

signature protosig_bittorrent_tracker {
  	ip-proto == tcp
  	payload /^HTTP\/[0-9]/
  	tcp-state responder
  	requires-reverse-signature protosig_bittorrent_tracker_client
  	eval ProtoSig::match
}

signature protosig_bittorrent_peer1 {
  	ip-proto == tcp
  	payload /^\x13BitTorrent protocol/
  	tcp-state originator
}

signature protosig_bittorrent {
  	ip-proto == tcp
  	payload /^\x13BitTorrent protocol/
  	tcp-state responder
  	requires-reverse-signature protosig_bittorrent_peer1
  	eval ProtoSig::match
}

signature protosig_ccattack {
	ip-proto == tcp
	# CCattack has Cache-Control field and 
	# value is no-cache or no-store or must-revalidate
    	payload /(|.*[\r\n])Cache-Control: [nm][ou][-s][sct][ta-][ocr][rhe]/
    	tcp-state responder 
    	eval ProtoSig::match
}
