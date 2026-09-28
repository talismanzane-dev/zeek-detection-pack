##! zeek-detection-pack lab configuration.
##!
##! Loads Zeek's default site policy, switches all logs to JSON (the zdp reader
##! auto-detects TSV or JSON) and logs SMB file writes, which Zeek omits from
##! smb_files.log by default but the lateral_movement detector scores.

@load local
@load policy/tuning/json-logs.zeek

# Zeek logs only FILE_OPEN/RENAME/DELETE by default; executable *writes* to
# admin shares are the strongest lateral-movement signal (score 0.9).
redef SMB::logged_file_actions += { SMB::FILE_WRITE };

# Synthetic and replayed captures may carry offloaded/invalid checksums.
redef ignore_checksums = T;
