From Coq Require Import List ZArith.
From compcert Require Import AST Values Memory.
From Bma400 Require Import BulkRead ObjectClass.

(* The map layout of a particular kernel build supplies [field].  Only the
   device's actual register address, count and byte stride specialize the rule. *)
Theorem kx022a_spi_three_axes (object noop : block) (field : Z)
    m g r advance convert p :
  window object noop field m g r 6 ->
  finish_at 6 6
    (run_loop advance convert (fun i => classify object noop field (r i)) offsets) p =
  finish_at 6 6
    (optimized advance convert (classify object noop field g)
      (fun i => classify object noop field (r i)) offsets) p.
Proof. apply one_byte_bulk. Qed.

Print Assumptions kx022a_spi_three_axes.
