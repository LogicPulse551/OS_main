(* Computational equation derived from the ORIGINAL iterator, no new axiom. *)
Require Import List ZArith Maps Integers Syntax Semantics ConstProp Cases Coqlib Iteration Wfsimpl.
Lemma iter_unfold A B (step:A -> B + A) n s :
 @PrimIter.iter A B step n s =
 match peq n 1%positive with
 | left _ => None
 | right _ => match step s with
              | inl res => Some res
              | inr next => @PrimIter.iter A B step (Pos.pred n) next
              end
 end.
Proof. unfold PrimIter.iter at 1. rewrite unroll_Fix. reflexivity. Qed.
Opaque PrimIter.iter.
Ltac cp_eval :=
 cbn -[PrimIter.iter];
 unfold ConstProp.transform_func, ValAnalysis.ValDS.analyze_func,
 ValAnalysis.ValDS.fixpoint_blk, ValAnalysis.ValDS.fixpoint,
 ValAnalysis.ValDS.fixpoint_from, PrimIter.iterate;
 cbn -[PrimIter.iter];
 repeat (rewrite iter_unfold; cbn -[PrimIter.iter]).
Definition cp_expected := single
 (Inst.assign 1%positive (value 7) ## Inst.assign 2%positive (value 12) ##
  Inst.print (reg 2%positive) ## BBlock.ret).
Lemma cp_actual_output : cp_output = Some cp_expected.
Proof. unfold cp_output, cp_input, cp_expected, single. cp_eval. reflexivity. Qed.
