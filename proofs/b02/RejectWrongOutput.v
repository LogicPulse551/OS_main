(* Expected to fail: a wrong transformed value must not acquire a proof. *)
Require Import List ZArith Maps Integers Event Syntax Semantics ConstProp Cases Evaluation.
Open Scope Z_scope.
Definition wrong := single
 (Inst.assign 1%positive (value 7) ## Inst.assign 2%positive (value 13) ##
  Inst.print (reg 2%positive) ## BBlock.ret).
Example wrong_value : result_view cp_output = Some (code_view wrong).
Proof. rewrite cp_actual_output. vm_compute. reflexivity. Qed.
