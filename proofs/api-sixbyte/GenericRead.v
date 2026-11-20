(* A call site's register is copied verbatim to both outcomes. Only the
   constructor and the callback-slot frame of its own map enter the rule. *)
From Coq Require Import ZArith List.
From compcert Require Import AST Values Memory Clight.
From Bma400 Require Import BulkRead Original Private ObjectClass
  ClightBinding EmittedBinding PrivateGuard.

Theorem any_start_six (addr : nat) (object : block) field m g reads advance convert p :
  window object PrivateGuard.known_code field m g reads 6 ->
  fn_body Private.f_kconc_sixbyte_guarded =
    guard_loops (fn_body Original.f_regmap_bulk_read) /\
  finish_at addr 6
    (run_loop advance convert
      (fun i => classify object PrivateGuard.known_code field (reads i)) offsets) p =
  finish_at addr 6
    (optimized advance convert (classify object PrivateGuard.known_code field g)
      (fun i => classify object PrivateGuard.known_code field (reads i)) offsets) p.
Proof.
  intro W. split; [exact emitted_cut | eapply one_byte_bulk; exact W].
Qed.

Print Assumptions any_start_six.
