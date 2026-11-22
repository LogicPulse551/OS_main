test "$mode" = natural
printf 'board_read_order=%s\n' "$planned_order" >> run.env
reader_rc=0
"$payload/read-axes" "$device" "/sys/module/$board/parameters" "$planned_order" > ops.tsv || reader_rc=$?
echo "reader_exit=$reader_rc" >> run.env
echo "IIO_PAIR order=$planned_order actor_exit=$reader_rc"
