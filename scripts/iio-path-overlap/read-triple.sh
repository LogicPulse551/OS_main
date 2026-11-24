test "$mode" = natural
test -r "$device/in_accel_z_raw"
printf 'board_read_order=X{Y,Z}\n' >> run.env
reader_rc=0
"$payload/read-axes" "$device" "/sys/module/$board/parameters" > ops.tsv || reader_rc=$?
printf 'reader_exit=%s\n' "$reader_rc" >> run.env
printf 'IIO_TRIPLE owner=X peers=Y,Z actor_exit=%s\n' "$reader_rc"
