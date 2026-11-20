(* The generated private AST, the two supported starting registers, and
   the frame condition share the conversion suffix checked by the class rule. *)
From Coq Require Import ZArith List.
From compcert Require Import AST Values Memory Clight.
From Bma400 Require Import BulkRead Original Private ObjectClass Kx022aRead
  ClightBinding EmittedBinding PrivateGuard.

Definition same_read_at addr object code field g reads advance convert p :=
  finish_at addr 6
    (run_loop advance convert (fun i => classify object code field (reads i)) offsets) p =
  finish_at addr 6
    (optimized advance convert (classify object code field g)
      (fun i => classify object code field (reads i)) offsets) p.

(* Field offsets are supplied by the corresponding Linux build. The separate
   guard-evaluation proof for the reduced Clight structure uses its own layout. *)
Theorem both_driver_reads (object : block) field m g reads advance convert p :
  window object PrivateGuard.known_code field m g reads 6 ->
  fn_body Private.f_kconc_sixbyte_guarded =
    guard_loops (fn_body Original.f_regmap_bulk_read) /\
  same_read_at 4 object PrivateGuard.known_code field g reads advance convert p /\
  same_read_at 6 object PrivateGuard.known_code field g reads advance convert p.
Proof.
  intro W. split; [exact emitted_cut|].
  split; unfold same_read_at.
  - eapply one_byte_bulk; exact W.
  - eapply kx022a_spi_three_axes; exact W.
Qed.

Print Assumptions both_driver_reads.
