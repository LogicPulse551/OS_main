(* The offsets below describe the projection. The memory frame and byte
   effects do not depend on where the full Linux object is placed. *)
From Coq Require Import List ZArith Bool Lia.
From compcert Require Import Coqlib Maps Integers AST Memory Values Events Ctypes Cop
  Clight Clightdefs ClightBigstep.
From Bma400 Require Import BulkRead Original ClightBinding ObjectClass VariableRead InitTarget InitGuard.
Import ListNotations InitTarget.
Local Open Scope Z_scope.

Definition object_expr := Ederef (Etempvar _map (tptr (Tstruct _regmap noattr))) (Tstruct _regmap noattr).
Definition qualifier := Efield object_expr _kconc_skip_noop tbool.
Definition width_field := Efield (Efield object_expr _format (Tstruct _regmap_format noattr)) _val_bytes tulong.
Definition guard_off := Eunop Onotbool (Etempvar _enabled tbool) tint.
Definition multi := Ebinop One width_field (literal 1) tint.
Definition stop_when x := Sifthenelse x (Sreturn None) Sskip.
Definition set_qualified := Sassign qualifier (literal 1).
Definition constructor := Ssequence (stop_when guard_off) (Ssequence (stop_when multi)
                          (Ssequence (stop_when different_callback) set_qualified)).
Definition disabled := Eunop Onotbool qualifier tint.
Definition select_first := clause disabled zero_count _t'3.
Definition select_last := clause (flag _t'3) too_long _t'4.
Definition dispatch := Sifthenelse (flag _t'4) callback_loop Sskip.
Definition cut := Ssequence (Ssequence select_first select_last) dispatch.

Definition ren i :=
  if Pos.eqb i Original._t'3 then _t'5 else
  if Pos.eqb i Original._t'4 then _t'6 else
  if Pos.eqb i Original._t'5 then _t'7 else i.
Fixpoint expr e :=
  match e with
  | Etempvar i t => Etempvar (ren i) t | Ederef a t => Ederef (expr a) t
  | Efield a f t => Efield (expr a) f t | Ecast a t => Ecast (expr a) t
  | Eunop op a t => Eunop op (expr a) t | Ebinop op a b t => Ebinop op (expr a) (expr b) t
  | other => other end.
Fixpoint replace s :=
  match s with
  | Ssequence (Sset _ _) (Sloop _ _) => cut
  | Ssequence a b => Ssequence (replace a) (replace b)
  | Sifthenelse e a b => Sifthenelse (expr e) (replace a) (replace b)
  | Sreturn e => Sreturn (option_map expr e) | Sset i e => Sset (ren i) (expr e)
  | Scall i f args => Scall (option_map ren i) (expr f) (map expr args)
  | other => other end.
Theorem actual_functions :
  fn_body f_kconc_bind_bulk_format = constructor /\
  loops (fn_body Original.f_regmap_bulk_read) = [callback_loop] /\
  fn_body f_kconc_init_bulk_read = replace (fn_body Original.f_regmap_bulk_read).
Proof. repeat split; reflexivity. Qed.

Lemma choose_then g e le m x on tail t le' m' out :
  eval_expr g e le m x (bit on) -> typeof x = tint ->
  (if on then (t=E0 /\ le'=le /\ m'=m /\ out=Out_return None)
   else exec_stmt g e le m tail t le' m' out) ->
  exec_stmt g e le m (Ssequence (stop_when x) tail) t le' m' out.
Proof.
  intros E T D; destruct on.
  - destruct D as [-> [-> [-> ->]]]. eapply exec_Sseq_2; [|discriminate].
    apply (if_bit _ _ _ _ _ true); auto. apply exec_Sreturn_none.
  - eapply exec_Sseq_1 with (t1:=E0) (t2:=t); [|exact D].
    apply (if_bit _ _ _ _ _ false); auto. apply exec_Sskip.
Qed.

Lemma class_location e le m obj :
  PTree.get _map le = Some (Vptr obj Ptrofs.zero) ->
  eval_lvalue InitGuard.guard_ge e le m qualifier obj (Ptrofs.repr 32) Full.
Proof.
  intro H. unfold qualifier,object_expr.
  change (Ptrofs.repr 32) with (Ptrofs.add Ptrofs.zero (Ptrofs.repr 32)).
  eapply eval_Efield_struct.
  - eapply eval_Elvalue.
    + apply eval_Ederef;apply eval_Etempvar;exact H.
    + apply deref_loc_copy;reflexivity.
  - reflexivity.
  - vm_compute;reflexivity.
  - vm_compute;reflexivity.
Qed.
Lemma format_width e le m obj w :
  PTree.get _map le = Some (Vptr obj Ptrofs.zero) -> Mem.load Mint64 m obj 0 = Some (Vlong w) ->
  eval_expr InitGuard.guard_ge e le m width_field (Vlong w).
Proof.
  intros M W. unfold width_field,object_expr.
  eapply eval_Elvalue.
  - eapply eval_Efield_struct.
    + eapply eval_Elvalue.
      * eapply eval_Efield_struct.
        -- eapply eval_Elvalue; [apply eval_Ederef;apply eval_Etempvar;exact M|apply deref_loc_copy;reflexivity].
        -- reflexivity.
        -- vm_compute;reflexivity.
        -- vm_compute;reflexivity.
      * apply deref_loc_copy;reflexivity.
    + reflexivity.
    + vm_compute;reflexivity.
    + vm_compute;reflexivity.
  - eapply deref_loc_value;[reflexivity|exact W].
Qed.
Lemma bind_positive e le m obj published :
  PTree.get _enabled le = Some (bit true) -> PTree.get _regmap_parse_inplace_noop e=None ->
  PTree.get _map le=Some (Vptr obj Ptrofs.zero) ->
  Mem.load Mint64 m obj 0=Some (Vlong Int64.one) -> installed obj InitGuard.known_code 8 m ->
  Mem.weak_valid_pointer m InitGuard.known_code 0=true ->
  Mem.store Mint8unsigned m obj 32 (bit true)=Some published ->
  exec_stmt InitGuard.guard_ge e le m constructor E0 le published Out_normal.
Proof.
  intros E LOCAL MAP W P LIVE S. unfold constructor.
  apply (choose_then _ _ _ _ _ false); [eapply eval_Eunop;[apply eval_Etempvar;exact E|reflexivity]|reflexivity|].
  apply (choose_then _ _ _ _ _ false); [eapply eval_Ebinop;
           [eapply format_width;eauto|apply eval_Econst_int|reflexivity]|reflexivity|].
  apply (choose_then _ _ _ _ _ false); [eapply InitGuard.actual_guard_false;eauto|reflexivity|].
  eapply exec_Sassign; [eapply class_location;exact MAP|apply eval_Econst_int|reflexivity|].
  eapply assign_loc_value;[reflexivity|exact S].
Qed.

Theorem bind_format e le m off wide other :
  eval_expr InitGuard.guard_ge e le m guard_off (bit off) ->
  (off=false -> eval_expr InitGuard.guard_ge e le m multi (bit wide)) ->
  (off=false -> wide=false -> eval_expr InitGuard.guard_ge e le m different_callback (bit other)) ->
  (off || wide || other)%bool = true ->
  exec_stmt InitGuard.guard_ge e le m (fn_body f_kconc_bind_bulk_format) E0 le m (Out_return None).
Proof.
  intros O W P D. rewrite (proj1 actual_functions).
  unfold constructor. apply (choose_then _ _ _ _ _ off); [exact O|reflexivity|].
  destruct off;[repeat split|]. apply (choose_then _ _ _ _ _ wide); [apply W;reflexivity|reflexivity|].
  destruct wide;[repeat split|]. apply (choose_then _ _ _ _ _ other); [apply P;reflexivity|reflexivity|].
  destruct other;[repeat split|discriminate].
Qed.

Definition footprint (obj b:block) i := b=obj /\ (0<=i<16 \/ i=32).
Theorem initial_class_stable m published g obj :
  Mem.load Mint64 m obj 0=Some (Vlong Int64.one) -> installed obj InitGuard.known_code 8 m ->
  Mem.store Mint8unsigned m obj 32 (bit true)=Some published ->
  Mem.unchanged_on (footprint obj) published g ->
  Mem.load Mint64 g obj 0=Some (Vlong Int64.one) /\ installed obj InitGuard.known_code 8 g /\
  Mem.load Mint8unsigned g obj 32=Some (bit true).
Proof.
  intros W P S F. unfold installed in *. repeat split.
  - eapply Mem.load_unchanged_on; [exact F|intros i I;split;auto;left;change (0<=i<0+8) in I;lia|].
    rewrite (Mem.load_store_other _ _ _ _ _ _ S); [exact W|right;left;change (0+8<=32);lia].
  - eapply Mem.load_unchanged_on; [exact F|intros i I;split;auto;left;change (8<=i<8+8) in I;lia|].
    rewrite (Mem.load_store_other _ _ _ _ _ _ S); [exact P|right;left;change (8+8<=32);lia].
  - eapply Mem.load_unchanged_on; [exact F|intros i I;split;auto;right;change (32<=i<32+1) in I;lia|].
    exact (Mem.load_store_same _ _ _ _ _ _ S).
Qed.

Lemma qualification_value e le m obj yes :
  PTree.get _map le=Some (Vptr obj Ptrofs.zero) -> Mem.load Mint8unsigned m obj 32=Some (bit yes) ->
  eval_expr InitGuard.guard_ge e le m disabled (bit (negb yes)).
Proof.
  intros M Q. eapply eval_Eunop.
  - apply eval_Elvalue with (loc:=obj) (ofs:=Ptrofs.repr 32) (bf:=Full).
    + apply class_location;exact M.
    + eapply deref_loc_value; [reflexivity|exact Q].
  - destruct yes; reflexivity.
Qed.
Theorem read_dispatch e le m obj yes zero large t le' m' out :
  let a := (negb yes || zero)%bool in let keep := (a || large)%bool in
  let le1 := record_bit _t'3 a le in let le2 := record_bit _t'4 keep le1 in
  PTree.get _map le=Some (Vptr obj Ptrofs.zero) ->
  Mem.load Mint8unsigned m obj 32=Some (bit yes) ->
  (negb yes=false -> eval_expr InitGuard.guard_ge e le m (Ecast zero_count tbool) (bit zero)) ->
  (a=false -> eval_expr InitGuard.guard_ge e le1 m (Ecast too_long tbool) (bit large)) ->
  exec_stmt InitGuard.guard_ge e le2 m (if keep then callback_loop else Sskip) t le' m' out ->
  exec_stmt InitGuard.guard_ge e le m cut t le' m' out.
Proof.
  intros a keep le1 le2 M Q Z L R. unfold cut.
  eapply exec_Sseq_1 with (t1:=E0) (t2:=t) (le1:=le2) (m1:=m).
  - eapply exec_Sseq_1 with (t1:=E0) (t2:=E0) (le1:=le1) (m1:=m).
    + apply exec_clause; [eapply qualification_value;eauto|left;reflexivity|exact Z].
    + apply exec_clause; [apply temp_bit|left;reflexivity|exact L].
  - eapply (if_bit _ _ _ _ _ keep); [apply temp_bit|left;reflexivity|exact R].
Qed.

Theorem disabled_instance ec lc m obj g er lr t lr' g' out :
  PTree.get _enabled lc = Some (bit false) ->
  Mem.load Mint8unsigned m obj 32 = Some (bit false) ->
  Mem.unchanged_on (footprint obj) m g ->
  PTree.get _map lr = Some (Vptr obj Ptrofs.zero) ->
  exec_stmt InitGuard.guard_ge er (record_bit _t'4 true (record_bit _t'3 true lr)) g
            callback_loop t lr' g' out ->
  exec_stmt InitGuard.guard_ge ec lc m (fn_body f_kconc_bind_bulk_format) E0 lc m (Out_return None) /\
  exec_stmt InitGuard.guard_ge er lr g cut t lr' g' out.
Proof.
  intros E Z F M L. split.
  - apply (bind_format _ _ _ true false false);
      [ eapply eval_Eunop;[apply eval_Etempvar;exact E|reflexivity] | discriminate | discriminate | reflexivity ].
  - apply (read_dispatch _ _ _ obj false false false); [exact M| |discriminate|discriminate|exact L].
    eapply Mem.load_unchanged_on;[exact F| |exact Z].
    intros i I;split;auto;right;change (32<=i<32+1) in I;lia.
Qed.

Theorem checked_read addr n m published g reads obj ec lc er lr advance convert p :
  0 < Z.of_nat n <= limit ->
  PTree.get _enabled lc=Some (bit true) -> PTree.get _regmap_parse_inplace_noop ec=None ->
  PTree.get _map lc=Some (Vptr obj Ptrofs.zero) ->
  Mem.load Mint64 m obj 0=Some (Vlong Int64.one) -> installed obj InitGuard.known_code 8 m ->
  Mem.weak_valid_pointer m InitGuard.known_code 0=true ->
  Mem.store Mint8unsigned m obj 32 (bit true)=Some published ->
  Mem.unchanged_on (footprint obj) published g ->
  (forall i,(i<n)%nat -> Mem.unchanged_on (footprint obj) published (reads i)) ->
  PTree.get _map lr=Some (Vptr obj Ptrofs.zero) ->
  PTree.get _val_count lr=Some (Vlong (Int64.repr (Z.of_nat n))) ->
  exec_stmt InitGuard.guard_ge ec lc m (fn_body f_kconc_bind_bulk_format) E0 lc published Out_normal /\
  eval_expr InitGuard.guard_ge er lr g width_field (Vlong Int64.one) /\
  (exists lr', exec_stmt InitGuard.guard_ge er lr g cut E0 lr' g Out_normal) /\
  indices (S n) Int.zero (Z.of_nat n)=Some (seq 0 n) /\
  finish_at addr n (run_loop advance convert (fun i=>classify obj InitGuard.known_code 8 (reads i)) (seq 0 n)) p =
  finish_at addr n (run_environment advance (seq 0 n)) p.
Proof.
  intros N E LOCAL MC W P LIVE S FG FR MR CNT.
  destruct (initial_class_stable _ _ _ _ W P S FG) as [WG [PG Q]].
  repeat split.
  - apply bind_positive with (obj:=obj);auto.
  - eapply format_width;eauto.
  - eexists. apply (read_dispatch _ _ _ obj true false false);[exact MR|exact Q| | |apply exec_Sskip].
    + intros _. exact (proj1 (constant_length_checks _ _ _ _ _ N CNT)).
    + intros _. assert (C: PTree.get _val_count (record_bit _t'3 false lr)=Some (Vlong (Int64.repr (Z.of_nat n)))).
      { unfold record_bit;rewrite PTree.gso by discriminate;exact CNT. }
      exact (proj2 (constant_length_checks _ _ _ _ _ N C)).
  - apply machine_indices;lia.
  - destruct p as [r|r|r];cbn [finish_at];try reflexivity.
    destruct (Z.eqb (rc r) 0);[|reflexivity].
    rewrite empty_loop;[reflexivity|]. intros i I. apply recognizes.
    apply in_seq in I. exact (proj1 (proj2 (initial_class_stable _ _ _ _ W P S (FR i ltac:(lia))))).
Qed.

Print Assumptions actual_functions.
Print Assumptions bind_format.
Print Assumptions initial_class_stable.
Print Assumptions read_dispatch.
Print Assumptions disabled_instance.
Print Assumptions checked_read.
Print Assumptions VariableRead.machine_indices.
Print Assumptions VariableRead.machine_expressions.
Print Assumptions InitGuard.linked_empty_callback.
