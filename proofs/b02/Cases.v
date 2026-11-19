(* Project-authored model inputs. Calls the unmodified B02 optimizers. *)
Require Import List ZArith String.
Require Import Maps Integers Event Syntax Semantics CorrectOpt.
Require Import ConstProp CSE DCE LICM DetLoop VerifiedOpt.
Import ListNotations.
Open Scope Z_scope.

Definition non_atomic : Ordering.LocOrdMap := fun _ => Ordering.nonatomic.
Definition atomic : Ordering.LocOrdMap := fun _ => Ordering.atomic.
Definition value (z:Z) := Inst.expr_val (Int.repr z).
Definition reg (p:positive) := Inst.expr_reg p.
Definition single (b:BBlock.t) : Code :=
  PTree.set 1%positive (PTree.set 1%positive b (PTree.empty BBlock.t),1%positive) (PTree.empty Func).
Definition add := Inst.expr_op2 Op2.add.
Definition cp_input := single
  (Inst.assign 1%positive (value 7) ##
   Inst.assign 2%positive (add (reg 1%positive) (value 5)) ##
   Inst.print (reg 2%positive) ## BBlock.ret).
Definition cp_boundary := single
  (Inst.load 1%positive 1%positive Ordering.acqrel ##
   Inst.assign 2%positive (add (reg 1%positive) (value 5)) ##
   Inst.print (reg 2%positive) ## BBlock.ret).
Definition expression := add (reg 8%positive) (reg 9%positive).
Definition cse_input := single
  (Inst.assign 1%positive expression ## Inst.assign 2%positive expression ##
   Inst.print (reg 2%positive) ## BBlock.ret).
Definition cse_boundary := single
  (Inst.assign 1%positive expression ## Inst.assign 8%positive (value 4) ##
   Inst.assign 2%positive expression ## Inst.print (reg 2%positive) ## BBlock.ret).
Definition dce_input := single
  (Inst.assign 1%positive (value 7) ## Inst.assign 2%positive (value 12) ##
   Inst.print (reg 2%positive) ## BBlock.ret).
Definition dce_boundary := single (Inst.print (value 7) ## Inst.fence_sc ## BBlock.ret).

Definition loop_function (ord:Ordering.t) (print_inside:bool) : Func :=
  (PTree.set 1%positive (Inst.assign 9%positive (value 2) ## BBlock.jmp 2%positive)
   (PTree.set 2%positive (BBlock.be (reg 9%positive) 3%positive 5%positive)
   (PTree.set 3%positive
      (Inst.load 1%positive 1%positive ord ##
       (if print_inside then Inst.print (reg 1%positive) ## BBlock.jmp 4%positive
        else BBlock.jmp 4%positive))
   (PTree.set 4%positive
      (Inst.assign 9%positive (Inst.expr_op2 Op2.sub (reg 9%positive) (value 1)) ##
       BBlock.jmp 2%positive)
   (PTree.set 5%positive (if print_inside then BBlock.ret else Inst.print (reg 1%positive) ## BBlock.ret)
       (PTree.empty BBlock.t))))),1%positive).
Definition licm_input : Code := PTree.set 1%positive (loop_function Ordering.plain false) (PTree.empty Func).
Definition licm_boundary : Code := PTree.set 1%positive (loop_function Ordering.acqrel false) (PTree.empty Func).
Definition licm_print_boundary : Code := PTree.set 1%positive (loop_function Ordering.plain true) (PTree.empty Func).

(* Small structural view: decimal integers, no erasure of access order or fences. *)
Definition order_view (o:Ordering.t) : Z :=
  match o with Ordering.plain=>0 | Ordering.relaxed=>1 | Ordering.strong_relaxed=>2 | Ordering.acqrel=>3 | Ordering.seqcst=>4 end.
Fixpoint expr_view (e:Inst.expr) : list Z :=
  match e with
  | Inst.expr_val v => [0; Int.signed v]
  | Inst.expr_reg r => [1; Z.pos r]
  | Inst.expr_op2 op a b =>
      [2; match op with Op2.add=>0 | Op2.sub=>1 | Op2.mul=>2 end] ++ expr_view a ++ expr_view b
  end.
Definition instr_view (i:Inst.t) : list Z :=
  match i with
  | Inst.skip => [0]
  | Inst.assign r e => [1; Z.pos r] ++ expr_view e
  | Inst.load r l o => [2;Z.pos r;Z.pos l;order_view o]
  | Inst.store l e o => [3;Z.pos l;order_view o] ++ expr_view e
  | Inst.print e => [4] ++ expr_view e
  | Inst.cas r l er ew or ow => [5;Z.pos r;Z.pos l;order_view or;order_view ow] ++ expr_view er ++ expr_view ew
  | Inst.fence_rel => [6] | Inst.fence_acq => [7] | Inst.fence_sc => [8]
  end.
Fixpoint block_view (b:BBlock.t) : list (list Z) :=
  match b with
  | BBlock.blk i b => instr_view i :: block_view b
  | BBlock.ret => [[9]]
  | BBlock.jmp l => [[10; Z.pos l]]
  | BBlock.call f r => [[11; Z.pos f; Z.pos r]]
  | BBlock.be e a b => ([12;Z.pos a;Z.pos b] ++ expr_view e)::nil
  end.
Definition code_view (p:Code) :=
  map (fun '(f,(blocks,entry)) =>
    (Z.pos f,Z.pos entry,map (fun '(l,b)=>(Z.pos l,block_view b)) (PTree.elements blocks))) (PTree.elements p).
Definition result_view (p:option Code) := option_map code_view p.

Definition cp_output := constprop_optimizer non_atomic cp_input.
Definition cse_output := cse_optimizer non_atomic cse_input.
Definition dce_output := dce_optimizer non_atomic dce_input.
Definition licm_output := licm non_atomic licm_input.

(* Specialize the dependent Language.syntax interface before OCaml extraction;
   extraction generates the coercions, the handwritten driver uses Code only. *)
Definition run_cp (lo:Ordering.LocOrdMap) (p:Code) : option Code := constprop_optimizer lo p.
Definition run_cse (lo:Ordering.LocOrdMap) (p:Code) : option Code := cse_optimizer lo p.
Definition run_dce (lo:Ordering.LocOrdMap) (p:Code) : option Code := dce_optimizer lo p.
Definition run_licm (lo:Ordering.LocOrdMap) (p:Code) : option Code := licm lo p.

(* Detailed evaluations and equalities are generated in fresh attempt directories
   by the runner, so every attempt retains its own inputs, outputs and proof log. *)
