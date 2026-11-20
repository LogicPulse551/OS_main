(* The original index is a signed C int, while val_count and val_bytes are
   size_t. The optimized domain is 1..INT_MAX on the fixed x86_64 ABI. *)
From Coq Require Import List ZArith Bool Lia.
From compcert Require Import Coqlib Maps Integers AST Memory Values Events Ctypes Cop
  Clight Clightdefs ClightBigstep.
From Bma400 Require Import BulkRead Original ClightBinding ObjectClass VarTarget VarGuard.
Import ListNotations.
Local Open Scope Z_scope.

Definition literal z := Econst_int (Int.repr z) tint.
Definition observer := Evar VarTarget._kconc_keep_callback_entries tbool.
Definition zero_count := Ebinop Oeq count (literal 0) tint.
Definition int_max_expr := Ecast
  (Ebinop Oshr (Eunop Onotint (Econst_int Int.zero tuint) tuint) (literal 1) tuint) tint.
Definition too_long := Ebinop Ogt count int_max_expr tint.
Definition wrong_width := Ebinop One width (literal 1) tint.
Definition clause condition argument id := Sifthenelse condition (Sset id (literal 1))
                                     (Sset id (Ecast argument tbool)).
Definition flag id := Etempvar id tint.
Definition test1 := clause observer zero_count VarTarget._t'3.
Definition test2 := clause (flag VarTarget._t'3) too_long VarTarget._t'4.
Definition test3 := clause (flag VarTarget._t'4) wrong_width VarTarget._t'5.
Definition test4 := clause (flag VarTarget._t'5) different_callback VarTarget._t'6.
Definition tests := Ssequence (Ssequence (Ssequence test1 test2) test3) test4.
Definition dispatch := Sifthenelse (flag VarTarget._t'6) callback_loop Sskip.
Definition cut := Ssequence tests dispatch.

Definition rename i :=
  if Pos.eqb i Original._t'3 then VarTarget._t'7 else
  if Pos.eqb i Original._t'4 then VarTarget._t'8 else
  if Pos.eqb i Original._t'5 then VarTarget._t'9 else i.
Fixpoint rename_expr e :=
  match e with
  | Etempvar i t => Etempvar (rename i) t
  | Ederef a t => Ederef (rename_expr a) t
  | Efield a f t => Efield (rename_expr a) f t
  | Ecast a t => Ecast (rename_expr a) t
  | Eunop op a t => Eunop op (rename_expr a) t
  | Ebinop op a b t => Ebinop op (rename_expr a) (rename_expr b) t
  | other => other
  end.
Fixpoint replace_cut s :=
  match s with
  | Ssequence (Sset _ _) (Sloop _ _) => cut
  | Ssequence a b => Ssequence (replace_cut a) (replace_cut b)
  | Sifthenelse e a b => Sifthenelse (rename_expr e) (replace_cut a) (replace_cut b)
  | Sreturn e => Sreturn (option_map rename_expr e)
  | Sset i e => Sset (rename i) (rename_expr e)
  | Scall i f args => Scall (option_map rename i) (rename_expr f) (map rename_expr args)
  | other => other
  end.
Theorem actual_function :
  loops (fn_body Original.f_regmap_bulk_read) = [callback_loop] /\
  fn_body VarTarget.f_kconc_valid_bulk_read = replace_cut (fn_body Original.f_regmap_bulk_read).
Proof. split; reflexivity. Qed.

Definition bit (b : bool) := if b then Vint Int.one else Vint Int.zero.
Definition record_bit i b (le : temp_env) := PTree.set i (bit b) le.
Lemma if_bit ge e le m expr b yes no t le' m' out :
  eval_expr ge e le m expr (bit b) -> (typeof expr = tint \/ typeof expr = tbool) ->
  exec_stmt ge e le m (if b then yes else no) t le' m' out ->
  exec_stmt ge e le m (Sifthenelse expr yes no) t le' m' out.
Proof.
  intros E T W. eapply exec_Sifthenelse; [exact E| |exact W].
  destruct T as [T | T]; rewrite T; destruct b; reflexivity.
Qed.
Lemma temp_bit ge e le m id b :
  eval_expr ge e (record_bit id b le) m (flag id) (bit b).
Proof. apply eval_Etempvar. apply PTree.gss. Qed.
Lemma exec_clause ge e le m c x id p q :
  eval_expr ge e le m c (bit p) -> (typeof c = tint \/ typeof c = tbool) ->
  (p = false -> eval_expr ge e le m (Ecast x tbool) (bit q)) ->
  exec_stmt ge e le m (clause c x id) E0 (record_bit id (p||q)%bool le) m Out_normal.
Proof.
  intros E T Q. apply (if_bit _ _ _ _ _ p); auto.
  destruct p; apply exec_Sset; [apply eval_Econst_int | apply Q; reflexivity].
Qed.

Theorem execute_selector ge e le m obs zero wide multi different :
  let a := (obs || zero)%bool in let b := (a || wide)%bool in
  let c := (b || multi)%bool in let d := (c || different)%bool in
  let le1 := record_bit VarTarget._t'3 a le in
  let le2 := record_bit VarTarget._t'4 b le1 in
  let le3 := record_bit VarTarget._t'5 c le2 in
  eval_expr ge e le m observer (bit obs) ->
  (obs = false -> eval_expr ge e le m (Ecast zero_count tbool) (bit zero)) ->
  (a = false -> eval_expr ge e le1 m (Ecast too_long tbool) (bit wide)) ->
  (b = false -> eval_expr ge e le2 m (Ecast wrong_width tbool) (bit multi)) ->
  (c = false -> eval_expr ge e le3 m (Ecast different_callback tbool) (bit different)) ->
  exec_stmt ge e le m tests E0 (record_bit VarTarget._t'6 d le3) m Out_normal.
Proof.
  intros a b c d le1 le2 le3 O Z B W P. unfold tests.
  eapply exec_Sseq_1 with (t1:=E0) (t2:=E0) (le1:=le3) (m1:=m).
  - eapply exec_Sseq_1 with (t1:=E0) (t2:=E0) (le1:=le2) (m1:=m).
    + eapply exec_Sseq_1 with (t1:=E0) (t2:=E0) (le1:=le1) (m1:=m).
      * apply exec_clause; [exact O|right;reflexivity|exact Z].
      * apply exec_clause; [apply temp_bit|left;reflexivity|exact B].
    + apply exec_clause; [apply temp_bit|left;reflexivity|exact W].
  - apply exec_clause; [apply temp_bit|left;reflexivity|exact P].
Qed.
Theorem dispatch_loop ge e le m keep t le' m' out :
  exec_stmt ge e (record_bit VarTarget._t'6 keep le) m (if keep then callback_loop else Sskip) t le' m' out ->
  exec_stmt ge e (record_bit VarTarget._t'6 keep le) m dispatch t le' m' out.
Proof. intro E. eapply if_bit; [apply temp_bit|left;reflexivity|exact E]. Qed.

Definition limit : Z := 2147483647.
Lemma int_bounds : Int.min_signed <= 0 /\ Int.max_signed = limit /\ limit <= Int64.max_unsigned.
Proof. vm_compute; intuition discriminate. Qed.

(* Interpret the original test after the signed int index is widened to
   unsigned long, then the original compound addition and conversion to int. *)
Definition less i (n : Z) := Int64.ltu (Int64.repr (Int.signed i)) (Int64.mul (Int64.repr n) Int64.one).
Definition next i := Int.repr (Int64.unsigned (Int64.add (Int64.repr (Int.signed i)) Int64.one)).
Definition loop_comparison := Ebinop Olt index (Ebinop Omul count width tulong) tint.
Definition loop_increment := Ecast (Ebinop Oadd index width tulong) tint.
Theorem machine_expressions ge e le m i n :
  PTree.get VarTarget._i le = Some (Vint i) ->
  PTree.get VarTarget._val_count le = Some (Vlong (Int64.repr n)) ->
  PTree.get VarTarget._val_bytes le = Some (Vlong Int64.one) ->
  eval_expr ge e le m loop_comparison (bit (less i n)) /\
  eval_expr ge e le m loop_increment (Vint (next i)).
Proof.
  intros I N W. split.
  - eapply eval_Ebinop with (v1:=Vint i) (v2:=Vlong (Int64.mul (Int64.repr n) Int64.one)).
    + eapply eval_Etempvar;exact I.
    + eapply eval_Ebinop;[eapply eval_Etempvar;exact N|eapply eval_Etempvar;exact W|reflexivity].
    + change (Some (Val.of_bool (less i n)) = Some (bit (less i n))).
      destruct (less i n);reflexivity.
  - eapply eval_Ecast; [eapply eval_Ebinop; [eapply eval_Etempvar;exact I|eapply eval_Etempvar;exact W|reflexivity]
                       |reflexivity].
Qed.
Lemma less_exact i n : 0 <= i <= limit -> 0 <= n <= limit ->
  less (Int.repr i) n = Z.ltb i n.
Proof.
  intros I N. destruct int_bounds as [MIN [MAX LARGE]].
  unfold less, Int64.ltu. rewrite Int.signed_repr by lia.
  rewrite Int64.mul_one. rewrite !Int64.unsigned_repr by lia.
  destruct (zlt i n); symmetry; [apply Z.ltb_lt|apply Z.ltb_ge]; lia.
Qed.
Lemma next_exact i : 0 <= i < limit -> next (Int.repr i) = Int.repr (i+1).
Proof.
  intro I. destruct int_bounds as [MIN [MAX LARGE]]. unfold next, Int64.add.
  rewrite Int.signed_repr by lia. change (Int64.unsigned Int64.one) with 1.
  rewrite (Int64.unsigned_repr i) by lia. rewrite Int64.unsigned_repr by lia. reflexivity.
Qed.
Fixpoint indices fuel i n : option (list nat) :=
  match fuel with
  | O => None
  | S rest => if less i n then
      match indices rest (next i) n with
      | Some xs => Some (Z.to_nat (Int.signed i)::xs) | None => None end
      else Some []
  end.
Lemma tail_indices k : forall start, Z.of_nat (start+k) <= limit ->
  indices (S k) (Int.repr (Z.of_nat start)) (Z.of_nat (start+k)) = Some (seq start k).
Proof.
  induction k as [|k IH]; intros start B.
  - rewrite Nat.add_0_r in *. cbn [indices]. rewrite less_exact by lia.
    now rewrite Z.ltb_irrefl.
  - change ((if less (Int.repr (Z.of_nat start)) (Z.of_nat (start+S k)) then
               match indices (S k) (next (Int.repr (Z.of_nat start))) (Z.of_nat (start+S k)) with
               | Some xs => Some (Z.to_nat (Int.signed (Int.repr (Z.of_nat start))) :: xs)
               | None => None end else Some []) = Some (seq start (S k))).
    rewrite less_exact by lia.
    assert (T : (Z.of_nat start <? Z.of_nat (start + S k)) = true) by (apply Z.ltb_lt;lia).
    rewrite T, next_exact by lia. replace (Z.of_nat start + 1) with (Z.of_nat (S start)) by lia.
    replace (start+S k)%nat with (S start+k)%nat in * by lia. rewrite IH by lia.
    destruct int_bounds as [MIN [MAX LARGE]]. rewrite Int.signed_repr by lia.
    rewrite Nat2Z.id. reflexivity.
Qed.
Theorem machine_indices n : Z.of_nat n <= limit ->
  indices (S n) Int.zero (Z.of_nat n) = Some (seq 0 n).
Proof. intro B. exact (tail_indices n 0%nat B). Qed.

Theorem api_read addr n obj code field m0 published g reads advance convert p :
  Mem.store Mint64 m0 obj field (Vptr code Ptrofs.zero) = Some published ->
  Mem.unchanged_on (slot obj field) published g ->
  (forall i, (i < n)%nat -> Mem.unchanged_on (slot obj field) published (reads i)) ->
  finish_at addr n (run_loop advance convert (fun i => classify obj code field (reads i)) (seq 0 n)) p =
  finish_at addr n (optimized advance convert (classify obj code field g)
      (fun i => classify obj code field (reads i)) (seq 0 n)) p.
Proof.
  intros STORE FG FR.
  assert (INIT : installed obj code field published) by (eapply initialize; eauto).
  assert (SAME : forall x, Mem.unchanged_on (slot obj field) published x ->
                    classify obj code field x = Empty).
  { intros x U. apply recognizes. eapply Mem.load_unchanged_on; [exact U| |exact INIT].
    intros i I; split; auto. }
  rewrite (SAME _ FG). simpl optimized.
  destruct p as [v|v|v]; cbn [finish_at]; try reflexivity.
  destruct (Z.eqb (rc v) 0); [|reflexivity].
  rewrite empty_loop; [reflexivity|intros i I; apply SAME, FR; apply in_seq in I; lia].
Qed.

Lemma constant_length_checks ge e le m n :
  0 < n <= limit -> PTree.get VarTarget._val_count le = Some (Vlong (Int64.repr n)) ->
  eval_expr ge e le m (Ecast zero_count tbool) (bit false) /\
  eval_expr ge e le m (Ecast too_long tbool) (bit false).
Proof.
  intros B L. destruct int_bounds as [MIN [MAX LARGE]].
  assert (U : Int64.unsigned (Int64.repr n) = n) by (apply Int64.unsigned_repr;lia).
  assert (MAX_EXPR : eval_expr ge e le m int_max_expr (Vint (Int.repr limit))).
  { eapply eval_Ecast; [eapply eval_Ebinop; [eapply eval_Eunop; [apply eval_Econst_int|reflexivity]
                                           |apply eval_Econst_int|reflexivity] |reflexivity]. }
  split; eapply eval_Ecast with (v1:=Vint Int.zero); [ | reflexivity | | reflexivity];
    eapply eval_Ebinop; [eapply eval_Etempvar;exact L |apply eval_Econst_int| |
                         eapply eval_Etempvar;exact L |exact MAX_EXPR| ].
  - change (Some (Val.of_bool (Int64.eq (Int64.repr n) Int64.zero)) = Some (Vint Int.zero)).
    unfold Int64.eq. rewrite U. change (Int64.unsigned Int64.zero) with 0.
    destruct (zeq n 0); [lia|reflexivity].
  - change (Some (Val.of_bool (Int64.ltu (Int64.repr limit) (Int64.repr n))) = Some (Vint Int.zero)).
    unfold Int64.ltu. rewrite U. rewrite Int64.unsigned_repr by lia.
    destruct (zlt limit n); [lia|reflexivity].
Qed.

Theorem oversized_check ge e le m n :
  limit < n <= Int64.max_unsigned ->
  PTree.get VarTarget._val_count le = Some (Vlong (Int64.repr n)) ->
  eval_expr ge e le m (Ecast too_long tbool) (bit true).
Proof.
  intros N L. assert (MAX_EXPR : eval_expr ge e le m int_max_expr (Vint (Int.repr limit))).
  { eapply eval_Ecast; [eapply eval_Ebinop; [eapply eval_Eunop; [apply eval_Econst_int|reflexivity]
                                           |apply eval_Econst_int|reflexivity] |reflexivity]. }
  eapply eval_Ecast with (v1:=Vint Int.one); [ | reflexivity].
  eapply eval_Ebinop; [eapply eval_Etempvar;exact L|exact MAX_EXPR|].
  change (Some (Val.of_bool (Int64.ltu (Int64.repr limit) (Int64.repr n))) = Some (Vint Int.one)).
  unfold Int64.ltu. assert (0 <= limit) by (unfold limit;lia).
  rewrite !Int64.unsigned_repr by lia. destruct (zlt limit n); [reflexivity|lia].
Qed.

Theorem fast_branch e le m obj n :
  0 < n <= limit ->
  PTree.get VarTarget._regmap_parse_inplace_noop e = None ->
  PTree.get VarTarget._map le = Some (Vptr obj Ptrofs.zero) ->
  PTree.get VarTarget._val_count le = Some (Vlong (Int64.repr n)) ->
  PTree.get VarTarget._val_bytes le = Some (Vlong (Int64.repr 1)) ->
  eval_expr VarGuard.guard_ge e le m observer (bit false) ->
  installed obj VarGuard.known_code 8 m -> Mem.weak_valid_pointer m VarGuard.known_code 0 = true ->
  exists le', exec_stmt VarGuard.guard_ge e le m cut E0 le' m Out_normal.
Proof.
  intros N LOCAL MAP COUNT WIDTH OBS INST LIVE.
  set (le1:=record_bit VarTarget._t'3 false le).
  set (le2:=record_bit VarTarget._t'4 false le1).
  set (le3:=record_bit VarTarget._t'5 false le2).
  exists (record_bit VarTarget._t'6 false le3). unfold cut.
  eapply exec_Sseq_1 with (t1:=E0) (t2:=E0) (m1:=m) (le1:=record_bit VarTarget._t'6 false le3).
  - apply (execute_selector _ _ _ _ false false false false false); simpl; [exact OBS| | | |].
    + intros _. exact (proj1 (constant_length_checks _ _ _ _ _ N COUNT)).
    + intros _. assert (C : PTree.get VarTarget._val_count le1 = Some (Vlong (Int64.repr n))).
      { unfold le1,record_bit. rewrite PTree.gso by discriminate. exact COUNT. }
      exact (proj2 (constant_length_checks _ _ _ _ _ N C)).
    + intros _. eapply eval_Ecast with (v1:=Vint Int.zero); [ |reflexivity].
      eapply eval_Ebinop; [eapply eval_Etempvar; unfold record_bit; rewrite !PTree.gso by discriminate; exact WIDTH
                          |apply eval_Econst_int|reflexivity].
    + intros _. eapply eval_Ecast.
      * eapply VarGuard.actual_guard_false; [exact LOCAL| |exact INST|exact LIVE].
        unfold record_bit. rewrite !PTree.gso by discriminate. exact MAP.
      * reflexivity.
  - apply (dispatch_loop _ _ _ _ false). apply exec_Sskip.
Qed.

Theorem checked_read addr (n:nat) obj m0 published g reads advance convert p e le :
  0 < Z.of_nat n <= limit ->
  Mem.store Mint64 m0 obj 8 (Vptr VarGuard.known_code Ptrofs.zero) = Some published ->
  Mem.unchanged_on (slot obj 8) published g ->
  (forall i, (i<n)%nat -> Mem.unchanged_on (slot obj 8) published (reads i)) ->
  PTree.get VarTarget._regmap_parse_inplace_noop e = None ->
  PTree.get VarTarget._map le = Some (Vptr obj Ptrofs.zero) ->
  PTree.get VarTarget._val_count le = Some (Vlong (Int64.repr (Z.of_nat n))) ->
  PTree.get VarTarget._val_bytes le = Some (Vlong (Int64.repr 1)) ->
  eval_expr VarGuard.guard_ge e le g observer (bit false) ->
  Mem.weak_valid_pointer g VarGuard.known_code 0 = true ->
  (exists le', exec_stmt VarGuard.guard_ge e le g cut E0 le' g Out_normal) /\
  indices (S n) Int.zero (Z.of_nat n) = Some (seq 0 n) /\
  finish_at addr n (run_loop advance convert (fun i=>classify obj VarGuard.known_code 8 (reads i)) (seq 0 n)) p =
  finish_at addr n (optimized advance convert (classify obj VarGuard.known_code 8 g)
        (fun i=>classify obj VarGuard.known_code 8 (reads i)) (seq 0 n)) p.
Proof.
  intros N ST FG FR LOCAL MAP COUNT WIDTH OBS LIVE. split.
  - eapply fast_branch; eauto. unfold installed.
    eapply Mem.load_unchanged_on; [exact FG|intros j I;split;auto|].
    exact (initialize obj VarGuard.known_code 8 m0 published ST).
  - split; [apply machine_indices;lia|eapply api_read;eauto].
Qed.

Print Assumptions actual_function.
Print Assumptions execute_selector.
Print Assumptions dispatch_loop.
Print Assumptions machine_indices.
Print Assumptions machine_expressions.
Print Assumptions oversized_check.
Print Assumptions api_read.
Print Assumptions checked_read.
