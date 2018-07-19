event file_sniff(f: fa_file, meta: fa_metadata)
{
    if(meta?$mime_type) {
        if(meta$mime_type == "application/javascript" || meta$mime_type == "application/x-executable") {
            local fuid = f$id;
            local fsource = f$source;
            local ftype = meta$mime_type;
            local fname = fmt("Extract - %s - %s", fsource, fuid);
            print fmt("*** Found %s in %s. Saved as %s. File ID is %s", ftype, fsource, fname, fuid);
            Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$ extract_filename = fname]);
        }
    }
}
