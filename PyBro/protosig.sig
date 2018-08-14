signature protosig_hi {
	ip-proto == tcp
	tcp-state originator
	eval ProtoSig::match
}

signature protosig_by {
	ip-proto == tcp
	tcp-state originator
	eval ProtoSig::match
}

signature protosig_u {
	ip-proto == tcp
	tcp-state originator
	eval ProtoSig::match
}

