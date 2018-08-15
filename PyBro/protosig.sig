signature protosig_ccattack {
	ip-proto == tcp
	payload /^HTTP\/[0-1].[0-9] 302 Found/
    payload /(|.*[\r\n])Cache-Control: [nm][ou][-s][sct][ta-][ocr][rhe]/
    tcp-state responder
	eval ProtoSig::match
}

signature protosig_fiestaSWF {
	ip-proto == tcp
    payload /(|.*[\r\n])GET \/[a-z0-9]{5,}\/[a-z0-9]{5,};118800/
    payload /(|.*[\r\n])x-flash-version: 11,8,800,94/
    tcp-state originator
    eval ProtoSig::match
}
