source :: Socket(UNIX_DGRAM, ~/adtn_source);
key :: Socket(UNIX_DGRAM, ~/adtn_key);
encoder :: aDTNChaCha20(1);
decoder :: aDTNChaCha20(0);
sink :: Socket(UNIX, ~/adtn_sink);

source -> [0]encoder;
encoder[0] -> [0]decoder;
decoder[0] -> sink;

key -> [1]encoder;
key -> [1]decoder;