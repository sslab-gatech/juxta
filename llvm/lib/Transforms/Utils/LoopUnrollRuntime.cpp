//===-- UnrollLoopRuntime.cpp - Runtime Loop unrolling utilities ----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements some loop unrolling utilities for loops with run-time
// trip counts.  See LoopUnroll.cpp for unrolling loops with compile-time
// trip counts.
//
// The functions in this file are used to generate extra code when the
// run-time trip count modulo the unroll factor is not 0.  When this is the
// case, we need to generate code to execute these 'left over' iterations.
//
// The current strategy generates an if-then-else sequence prior to the
// unrolled loop to execute the 'left over' iterations.  Other strategies
// include generate a loop before or after the unrolled loop.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Utils/UnrollLoop.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/LoopIterator.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpander.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <algorithm>

using namespace llvm;

#define DEBUG_TYPE "loop-unroll"

STATISTIC(NumRuntimeUnrolled,
          "Number of loops unrolled with run-time trip counts");

/// Connect the unrolling prolog code to the original loop.
/// The unrolling prolog code contains code to execute the
/// 'extra' iterations if the run-time trip count modulo the
/// unroll count is non-zero.
///
/// This function performs the following:
/// - Create PHI nodes at prolog end block to combine values
///   that exit the prolog code and jump around the prolog.
/// - Add a PHI operand to a PHI node at the loop exit block
///   for values that exit the prolog and go around the loop.
/// - Branch around the original loop if the trip count is less
///   than the unroll factor.
///
static void ConnectProlog(Loop *L, Value *TripCount, unsigned Count,
                          BasicBlock *LastPrologBB, BasicBlock *PrologEnd,
                          BasicBlock *OrigPH, BasicBlock *NewPH,
                          ValueToValueMapTy &VMap, Pass *P) {
  BasicBlock *Latch = L->getLoopLatch();
  assert(Latch && "Loop must have a latch");

  // Create a PHI node for each outgoing value from the original loop
  // (which means it is an outgoing value from the prolog code too).
  // The new PHI node is inserted in the prolog end basic block.
  // The new PHI name is added as an operand of a PHI node in either
  // the loop header or the loop exit block.
  for (succ_iterator SBI = succ_begin(Latch), SBE = succ_end(Latch);
       SBI != SBE; ++SBI) {
    for (BasicBlock::iterator BBI = (*SBI)->begin();
         PHINode *PN = dyn_cast<PHINode>(BBI); ++BBI) {

      // Add a new PHI node to the prolog end block and add the
      // appropriate incoming values.
      PHINode *NewPN = PHINode::Create(PN->getType(), 2, PN->getName()+".unr",
                                       PrologEnd->getTerminator());
      // Adding a value to the new PHI node from the original loop preheader.
      // This is the value that skips all the prolog code.
      if (L->contains(PN)) {
        NewPN->addIncoming(PN->getIncomingValueForBlock(NewPH), OrigPH);
      } else {
        NewPN->addIncoming(Constant::getNullValue(PN->getType()), OrigPH);
      }

      Value *V = PN->getIncomingValueForBlock(Latch);
      if (Instruction *I = dyn_cast<Instruction>(V)) {
        if (L->contains(I)) {
          V = VMap[I];
        }
      }
      // Adding a value to the new PHI node from the last prolog block
      // that was created.
      NewPN->addIncoming(V, LastPrologBB);

      // Update the existing PHI node operand with the value from the
      // new PHI node.  How this is done depends on if the existing
      // PHI node is in the original loop block, or the exit block.
      if (L->contains(PN)) {
        PN->setIncomingValue(PN->getBasicBlockIndex(NewPH), NewPN);
      } else {
        PN->addIncoming(NewPN, PrologEnd);
      }
    }
  }

  // Create a branch around the orignal loop, which is taken if the
  // trip count is less than the unroll factor.
  Instruction *InsertPt = PrologEnd->getTerminator();
  Instruction *BrLoopExit =
    new ICmpInst(InsertPt, ICmpInst::ICMP_ULT, TripCount,
                 ConstantInt::get(TripCount->getType(), Count));
  BasicBlock *Exit = L->getUniqueExitBlock();
  assert(Exit && "Loop must have a single exit block only");
  // Split the exit to maintain loop canonicalization guarantees
  SmallVector<BasicBlock*, 4> Preds(pred_begin(Exit), pred_end(Exit));
  if (!Exit->isLandingPad()) {
    SplitBlockPredecessors(Exit, Preds, ".unr-lcssa", P);
  } else {
    SmallVector<BasicBlock*, 2> NewBBs;
    SplitLandingPadPredecessors(Exit, Preds, ".unr1-lcssa", ".unr2-lcssa",
                                P, NewBBs);
  }
  // Add the branch to the exit block (around the unrolled loop)
  BranchInst::Create(Exit, NewPH, BrLoopExit, InsertPt);
  InsertPt->eraseFromParent();
}

/// Create a clone of the blocks in a loop and connect them together.
/// If UnrollProlog is true, loop structure will not be cloned, otherwise a new
/// loop will be created including all cloned blocks, and the iterator of it
/// switches to count NewIter down to 0.
///
static void CloneLoopBlocks(Loop *L, Value *NewIter, const bool UnrollProlog,
                            BasicBlock *InsertTop, BasicBlock *InsertBot,
                            std::vector<BasicBlock *> &NewBlocks,
                            LoopBlocksDFS &LoopBlocks, ValueToValueMapTy &VMap,
                            LoopInfo *LI) {
  BasicBlock *Preheader = L->getLoopPreheader();
  BasicBlock *Header = L->getHeader();
  BasicBlock *Latch = L->getLoopLatch();
  Function *F = Header->getParent();
  LoopBlocksDFS::RPOIterator BlockBegin = LoopBlocks.beginRPO();
  LoopBlocksDFS::RPOIterator BlockEnd = LoopBlocks.endRPO();
  Loop *NewLoop = 0;
  Loop *ParentLoop = L->getParentLoop();
  if (!UnrollProlog) {
    NewLoop = new Loop();
    if (ParentLoop)
      ParentLoop->addChildLoop(NewLoop);
    else
      LI->addTopLevelLoop(NewLoop);
  }

  // For each block in the original loop, create a new copy,
  // and update the value map with the newly created values.
  for (LoopBlocksDFS::RPOIterator BB = BlockBegin; BB != BlockEnd; ++BB) {
    BasicBlock *NewBB = CloneBasicBlock(*BB, VMap, ".prol", F);
    NewBlocks.push_back(NewBB);

    if (NewLoop)
      NewLoop->addBasicBlockToLoop(NewBB, LI->getBase());
    else if (ParentLoop)
      ParentLoop->addBasicBlockToLoop(NewBB, LI->getBase());

    VMap[*BB] = NewBB;
    if (Header == *BB) {
      // For the first block, add a CFG connection to this newly
      // created block.
      InsertTop->getTerminator()->setSuccessor(0, NewBB);

    }
    if (Latch == *BB) {
      // For the last block, if UnrollProlog is true, create a direct jump to
      // InsertBot. If not, create a loop back to cloned head.
      VMap.erase((*BB)->getTerminator());
      BasicBlock *FirstLoopBB = cast<BasicBlock>(VMap[Header]);
      BranchInst *LatchBR = cast<BranchInst>(NewBB->getTerminator());
      if (UnrollProlog) {
        LatchBR->eraseFromParent();
        BranchInst::Create(InsertBot, NewBB);
      } else {
        PHINode *NewIdx = PHINode::Create(NewIter->getType(), 2, "prol.iter",
                                          FirstLoopBB->getFirstNonPHI());
        IRBuilder<> Builder(LatchBR);
        Value *IdxSub =
            Builder.CreateSub(NewIdx, ConstantInt::get(NewIdx->getType(), 1),
                              NewIdx->getName() + ".sub");
        Value *IdxCmp =
            Builder.CreateIsNotNull(IdxSub, NewIdx->getName() + ".cmp");
        BranchInst::Create(FirstLoopBB, InsertBot, IdxCmp, NewBB);
        NewIdx->addIncoming(NewIter, InsertTop);
        NewIdx->addIncoming(IdxSub, NewBB);
        LatchBR->eraseFromParent();
      }
    }
  }

  // Change the incoming values to the ones defined in the preheader or
  // cloned loop.
  for (BasicBlock::iterator I = Header->begin(); isa<PHINode>(I); ++I) {
    PHINode *NewPHI = cast<PHINode>(VMap[I]);
    if (UnrollProlog) {
      VMap[I] = NewPHI->getIncomingValueForBlock(Preheader);
      cast<BasicBlock>(VMap[Header])->getInstList().erase(NewPHI);
    } else {
      unsigned idx = NewPHI->getBasicBlockIndex(Preheader);
      NewPHI->setIncomingBlock(idx, InsertTop);
      BasicBlock *NewLatch = cast<BasicBlock>(VMap[Latch]);
      idx = NewPHI->getBasicBlockIndex(Latch);
      Value *InVal = NewPHI->getIncomingValue(idx);
      NewPHI->setIncomingBlock(idx, NewLatch);
      if (VMap[InVal])
        NewPHI->setIncomingValue(idx, VMap[InVal]);
    }
  }
  if (NewLoop) {
    // Add unroll disable metadata to disable future unrolling for this loop.
    SmallVector<Value *, 4> Vals;
    // Reserve first location for self reference to the LoopID metadata node.
    Vals.push_back(nullptr);
    MDNode *LoopID = NewLoop->getLoopID();
    if (LoopID) {
      // First remove any existing loop unrolling metadata.
      for (unsigned i = 1, ie = LoopID->getNumOperands(); i < ie; ++i) {
        bool IsUnrollMetadata = false;
        MDNode *MD = dyn_cast<MDNode>(LoopID->getOperand(i));
        if (MD) {
          const MDString *S = dyn_cast<MDString>(MD->getOperand(0));
          IsUnrollMetadata = S && S->getString().startswith("llvm.loop.unroll.");
        }
        if (!IsUnrollMetadata) Vals.push_back(LoopID->getOperand(i));
      }
    }

    LLVMContext &Context = NewLoop->getHeader()->getContext();
    SmallVector<Value *, 1> DisableOperands;
    DisableOperands.push_back(MDString::get(Context, "llvm.loop.unroll.disable"));
    MDNode *DisableNode = MDNode::get(Context, DisableOperands);
    Vals.push_back(DisableNode);

    MDNode *NewLoopID = MDNode::get(Context, Vals);
    // Set operand 0 to refer to the loop id itself.
    NewLoopID->replaceOperandWith(0, NewLoopID);
    NewLoop->setLoopID(NewLoopID);
  }
}

/// Insert code in the prolog code when unrolling a loop with a
/// run-time trip-count.
///
/// This method assumes that the loop unroll factor is total number
/// of loop bodes in the loop after unrolling. (Some folks refer
/// to the unroll factor as the number of *extra* copies added).
/// We assume also that the loop unroll factor is a power-of-two. So, after
/// unrolling the loop, the number of loop bodies executed is 2,
/// 4, 8, etc.  Note - LLVM converts the if-then-sequence to a switch
/// instruction in SimplifyCFG.cpp.  Then, the backend decides how code for
/// the switch instruction is generated.
///
///        extraiters = tripcount % loopfactor
///        if (extraiters == 0) jump Loop:
///        else jump Prol
/// Prol:  LoopBody;
///        extraiters -= 1                 // Omitted if unroll factor is 2.
///        if (extraiters != 0) jump Prol: // Omitted if unroll factor is 2.
///        if (tripcount < loopfactor) jump End
/// Loop:
/// ...
/// End:
///
bool llvm::UnrollRuntimeLoopProlog(Loop *L, unsigned Count, LoopInfo *LI,
                                   LPPassManager *LPM) {
  // for now, only unroll loops that contain a single exit
  if (!L->getExitingBlock())
    return false;

  // Make sure the loop is in canonical form, and there is a single
  // exit block only.
  if (!L->isLoopSimplifyForm() || !L->getUniqueExitBlock())
    return false;

  // Use Scalar Evolution to compute the trip count.  This allows more
  // loops to be unrolled than relying on induction var simplification
  if (!LPM)
    return false;
  ScalarEvolution *SE = LPM->getAnalysisIfAvailable<ScalarEvolution>();
  if (!SE)
    return false;

  // Only unroll loops with a computable trip count and the trip count needs
  // to be an int value (allowing a pointer type is a TODO item)
  const SCEV *BECount = SE->getBackedgeTakenCount(L);
  if (isa<SCEVCouldNotCompute>(BECount) || !BECount->getType()->isIntegerTy())
    return false;

  // If BECount is INT_MAX, we can't compute trip-count without overflow.
  if (BECount->isAllOnesValue())
    return false;

  // Add 1 since the backedge count doesn't include the first loop iteration
  const SCEV *TripCountSC =
    SE->getAddExpr(BECount, SE->getConstant(BECount->getType(), 1));
  if (isa<SCEVCouldNotCompute>(TripCountSC))
    return false;

  // We only handle cases when the unroll factor is a power of 2.
  // Count is the loop unroll factor, the number of extra copies added + 1.
  if ((Count & (Count-1)) != 0)
    return false;

  // If this loop is nested, then the loop unroller changes the code in
  // parent loop, so the Scalar Evolution pass needs to be run again
  if (Loop *ParentLoop = L->getParentLoop())
    SE->forgetLoop(ParentLoop);

  BasicBlock *PH = L->getLoopPreheader();
  BasicBlock *Header = L->getHeader();
  BasicBlock *Latch = L->getLoopLatch();
  // It helps to splits the original preheader twice, one for the end of the
  // prolog code and one for a new loop preheader
  BasicBlock *PEnd = SplitEdge(PH, Header, LPM->getAsPass());
  BasicBlock *NewPH = SplitBlock(PEnd, PEnd->getTerminator(), LPM->getAsPass());
  BranchInst *PreHeaderBR = cast<BranchInst>(PH->getTerminator());

  // Compute the number of extra iterations required, which is:
  //  extra iterations = run-time trip count % (loop unroll factor + 1)
  SCEVExpander Expander(*SE, "loop-unroll");
  Value *TripCount = Expander.expandCodeFor(TripCountSC, TripCountSC->getType(),
                                            PreHeaderBR);

  IRBuilder<> B(PreHeaderBR);
  Value *ModVal = B.CreateAnd(TripCount, Count - 1, "xtraiter");

  // Check if for no extra iterations, then jump to cloned/unrolled loop.
  // We have to check that the trip count computation didn't overflow when
  // adding one to the backedge taken count.
  Value *LCmp = B.CreateIsNotNull(ModVal, "lcmp.mod");
  Value *OverflowCheck = B.CreateIsNull(TripCount, "lcmp.overflow");
  Value *BranchVal = B.CreateOr(OverflowCheck, LCmp, "lcmp.or");

  // Branch to either the extra iterations or the cloned/unrolled loop
  // We will fix up the true branch label when adding loop body copies
  BranchInst::Create(PEnd, PEnd, BranchVal, PreHeaderBR);
  assert(PreHeaderBR->isUnconditional() &&
         PreHeaderBR->getSuccessor(0) == PEnd &&
         "CFG edges in Preheader are not correct");
  PreHeaderBR->eraseFromParent();
  Function *F = Header->getParent();
  // Get an ordered list of blocks in the loop to help with the ordering of the
  // cloned blocks in the prolog code
  LoopBlocksDFS LoopBlocks(L);
  LoopBlocks.perform(LI);

  //
  // For each extra loop iteration, create a copy of the loop's basic blocks
  // and generate a condition that branches to the copy depending on the
  // number of 'left over' iterations.
  //
  std::vector<BasicBlock *> NewBlocks;
  ValueToValueMapTy VMap;

  // If unroll count is 2 and we can't overflow in tripcount computation (which
  // is BECount + 1), then we don't need a loop for prologue, and we can unroll
  // it. We can be sure that we don't overflow only if tripcount is a constant.
  bool UnrollPrologue = (Count == 2 && isa<ConstantInt>(TripCount));

  // Clone all the basic blocks in the loop. If Count is 2, we don't clone
  // the loop, otherwise we create a cloned loop to execute the extra
  // iterations. This function adds the appropriate CFG connections.
  CloneLoopBlocks(L, ModVal, UnrollPrologue, PH, PEnd, NewBlocks, LoopBlocks,
                  VMap, LI);

  // Insert the cloned blocks into function just before the original loop
  F->getBasicBlockList().splice(PEnd, F->getBasicBlockList(), NewBlocks[0],
                                F->end());

  // Rewrite the cloned instruction operands to use the values
  // created when the clone is created.
  for (unsigned i = 0, e = NewBlocks.size(); i != e; ++i) {
    for (BasicBlock::iterator I = NewBlocks[i]->begin(),
                              E = NewBlocks[i]->end();
         I != E; ++I) {
      RemapInstruction(I, VMap,
                       RF_NoModuleLevelChanges | RF_IgnoreMissingEntries);
    }
  }

  // Connect the prolog code to the original loop and update the
  // PHI functions.
  BasicBlock *LastLoopBB = cast<BasicBlock>(VMap[Latch]);
  ConnectProlog(L, TripCount, Count, LastLoopBB, PEnd, PH, NewPH, VMap,
                LPM->getAsPass());
  NumRuntimeUnrolled++;
  return true;
}
