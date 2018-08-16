module ProtoSig;

export {
	redef enum Notice::Type += {
		BitTorrent,
		DDos,
		Malware
	};

	redef record connection += {
		## The protocol detected purely by signature matching.
		protosig: string &optional &log;
	};

	redef record Conn::Info += {
		## The protocol detected purely by signature matching.
		protosig: string &optional &log;
	};
}

function ProtoSig::match(state: signature_state, data: string): bool
	{
	local proto = gsub(state$sig_id, /^protosig_/, "");
	state$conn$protosig = proto;

    # Start of Notice

	if ( /ccattack/ in state$sig_id ) {
		print("ccattack founded");
		NOTICE([$note=ProtoSig::Malware, $msg="ccattack founded",
            		$conn=state$conn, 
            		$identifier=fmt("%s%s", state$conn$id$orig_h, state$conn$id$resp_h)]);
	}

	if ( /fiestaSWF/ in state$sig_id ) {
		print("fiestaSWF founded");
		NOTICE([$note=ProtoSig::Malware, $msg="fiestaSWF founded",
            		$conn=state$conn, 
            		$identifier=fmt("%s%s", state$conn$id$orig_h, state$conn$id$resp_h)]);
	}
	# End of Notice


	# We just always return false because we're done.  We don't
	# actually want the signature match to happen.
	return F;
	}


event connection_state_remove(c: connection) &priority=3
	{
	if ( c?$protosig )
		c$conn$protosig = c$protosig;
	}

