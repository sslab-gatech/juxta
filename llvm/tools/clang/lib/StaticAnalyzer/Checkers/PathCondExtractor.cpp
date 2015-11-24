//== PathCondExtractor.cpp --------------------------------------------*- C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines PathCondExtractor, which prints out path conditions
// for each return code.
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/FssStmtPrinter.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Support/raw_ostream.h"
#include <utility>

using namespace clang;
using namespace ento;

namespace {
class PathCondExtractor : public Checker< check::PreStmt<ReturnStmt>, 
                                          check::PreStmt<BinaryOperator>,
                                          check::PreStmt<UnaryOperator>,
                                          check::PreStmt<CallExpr>,
                                          check::EndFunction,
                                          check::EndAnalysis > {
public:
  PathCondExtractor();
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const; 
  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;
  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;
  void checkEndFunction(CheckerContext &C) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &N) const;
private:
  // Bug type 
  std::unique_ptr<BugType> PathCondReportType;

  // RetMap = {return location + return value, 
  //               {path condition, node}* }*
  typedef std::pair<std::string, ExplodedNode *> RetCondPairTy; 
  typedef llvm::SmallVector<RetCondPairTy, 16> RetCondsTy;
  typedef llvm::StringMap<RetCondsTy> RetMapTy;
  mutable RetMapTy RetMap;

private: 
  void emitPathInfo(CheckerContext &C,
                    const FunctionDecl *FD, 
                    const ReturnStmt *RS,
                    ExplodedNode *N) const;
  void addToRetCond(const std::string &Key, 
                    const std::string &Value, 
                    ExplodedNode  *N) const;
  void condcat(llvm::raw_string_ostream &OS, RetCondsTy &Conds) const;
  void getRetSig(llvm::raw_string_ostream &OS, const FunctionDecl *FD,
                 const ReturnStmt *RS, CheckerContext &C) const;
  bool getPathCond(llvm::raw_string_ostream &OS, const FunctionDecl *FD,
                   std::string &Sig, CheckerContext &C) const;
  int getFunctionSummary(llvm::raw_string_ostream &OS, const FunctionDecl *FD,
                         CheckerContext &C) const;
  bool isInBlackList(CheckerContext &C, const FunctionDecl *FD) const;

  mutable IdentifierInfo *II___builtin_expect;
};
} // end anonymous namespace

PathCondExtractor::PathCondExtractor() 
  : II___builtin_expect(nullptr) {
  PathCondReportType.reset(
  new BugType(this, "Return path condition", "fs-semantics path condition extractor"));
}

void PathCondExtractor::addToRetCond(const std::string &Key, 
                                     const std::string &Value, 
                                     ExplodedNode *N) const {
  RetMap[Key].push_back( std::make_pair(Value, N) );
}

static 
void GetFuncName(llvm::raw_string_ostream &OS, const FunctionDecl *FD) {
  OS << FD->getDeclName().getAsString() << '('; 

  int i = 0;
  for (FunctionDecl::param_const_iterator I = FD->param_begin(),
         E = FD->param_end(); I != E; ++I, ++i) {
    const ParmVarDecl *PD = *I;
    QualType T = PD->getTypeSourceInfo()
      ? PD->getTypeSourceInfo()->getType()
      : PD->getASTContext().getUnqualifiedObjCPointerType(PD->getType());
    if (i) OS << ", ";
    OS << T.getUnqualifiedType().getAsString() << ' ' << *PD; 
  }

  OS << ')';
}

void PathCondExtractor::getRetSig(llvm::raw_string_ostream &OS,
                                  const FunctionDecl *FD,
                                  const ReturnStmt *RS, 
                                  CheckerContext &C) const {
  SourceManager &SM = C.getSourceManager();

  if (RS) 
    OS << RS->getReturnLoc().printToString(SM);
  else 
    OS << FD->getSourceRange().getEnd().printToString(SM);
  OS << "\n@FUNCTION: "; 
  GetFuncName(OS, FD); 
  OS << "\n@RETURN: "; 

  const Expr *RE = RS ? RS->getRetValue() : nullptr;
  if (RE) {
    FssStmtPrinter Printer(OS, C.getLocationContext(), C.getState(), 0, false);
    Printer.Visit(const_cast<Expr*>(RE));
  }
  else {
    OS << "nil";
  }
}

bool PathCondExtractor::getPathCond(llvm::raw_string_ostream &OS,
                                    const FunctionDecl *FD, 
                                    std::string &Sig, 
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  ProgramStateManager &Mgr = State->getStateManager();
  ConstraintManager &ConstMgr = Mgr.getConstraintManager();
  bool rc;

  OS << "\n@LOCATION: " << Sig;
  OS << "\n";

  if (!FD->getReturnType()->isVoidType()) {
    ConstMgr.print(C, State, OS);
    rc = true;
  }
  else {
    OS << "@CONDITION: nil\n";
    rc = false;
  }
  return rc;
}


static inline
const char *getHistoricalEventKindString(const HistoricalEvent *hxev) {
  switch (hxev->K) {
  case HistoricalEvent::BO_ASSIGN:
  case HistoricalEvent::UO_ASSIGN:
    return "STORE";
  case HistoricalEvent::FN_CALL:
    return "CALL";
  default:
    assert(0);
    return "UNKNOWN";
  }
}

int PathCondExtractor::getFunctionSummary(llvm::raw_string_ostream &OS,
                                           const FunctionDecl *FD, 
                                           CheckerContext &C) const {
  ProgramStateRef state = C.getState();

  int i = 0;
  for (ProgramState::hxev_const_iterator I = state->hxev_begin(),
         E = state->hxev_end(); I != E; ++I, ++i) {
    ProgramStateRef hxevState = *I;
    const HistoricalEvent *hxev = hxevState->getHistoricalEvent();

    FssStmtPrinter Printer(OS, hxev->LCtx, hxevState, 0, true);
    OS << "@LOG_" << getHistoricalEventKindString(hxev) << ": "; 
    Printer.Visit(const_cast<Stmt*>(hxev->S));
    OS << " @LOCATION: " 
       << hxev->S->getLocStart().printToString( C.getSourceManager() )
       << '\n';
  }
  return i;
}

void PathCondExtractor::checkPreStmt(const BinaryOperator *BO, 
                                     CheckerContext &C) const {
#ifdef FSS_FILTER_OUT_NON_TOP_FRAME
  if (!C.getLocationContext()->inTopFrame())
    return;
#endif 

  if ( HistoricalEvent::getKind(BO) != HistoricalEvent::BO_ASSIGN )
    return;

  C.getState()->recordHistoricalEvent(C,
                                      HistoricalEvent::BO_ASSIGN,
                                      static_cast<const Stmt*>(BO));
}

void PathCondExtractor::checkPreStmt(const UnaryOperator *UO, 
                                     CheckerContext &C) const {
#ifdef FSS_FILTER_OUT_NON_TOP_FRAME
  if (!C.getLocationContext()->inTopFrame())
    return;
#endif

  if ( HistoricalEvent::getKind(UO) != HistoricalEvent::UO_ASSIGN )
    return;

  C.getState()->recordHistoricalEvent(C,
                                      HistoricalEvent::UO_ASSIGN,
                                      static_cast<const Stmt*>(UO));
}

bool PathCondExtractor::isInBlackList(CheckerContext &C, 
                                      const FunctionDecl *FD) const {
  if (!FD) return false;

  const IdentifierInfo *II = FD->getIdentifier(); 
  ASTContext &Ctx = C.getASTContext();

  if (!II___builtin_expect) 
    II___builtin_expect = &Ctx.Idents.get("__builtin_expect");
  if (II___builtin_expect == II) 
    return true; 

  return false;
}

void PathCondExtractor::checkPreStmt(const CallExpr *CE,
                                     CheckerContext &C) const {
#ifdef FSS_FILTER_OUT_NON_TOP_FRAME
  if (!C.getLocationContext()->inTopFrame())
    return;
#endif

  if ( HistoricalEvent::getKind(CE) != HistoricalEvent::FN_CALL )
    return;

  if (isInBlackList(C, C.getCalleeDecl(CE)))
    return;

  C.getState()->recordHistoricalEvent(C,
                                      HistoricalEvent::FN_CALL,
                                      static_cast<const Stmt*>(CE));
}

void PathCondExtractor::emitPathInfo(CheckerContext &C, 
                                     const FunctionDecl *FD, 
                                     const ReturnStmt *RS,
                                     ExplodedNode *N) const {
  std::string *Key = new std::string;
  std::string *Value = new std::string;
  llvm::raw_string_ostream KS(*Key);
  llvm::raw_string_ostream VS(*Value);

  getRetSig(KS, FD, RS, C);
  bool havePathCond = getPathCond(VS, FD, KS.str(), C); 
  int numFuncSummary = getFunctionSummary(VS, FD, C);

  if (havePathCond || numFuncSummary > 0) 
    addToRetCond(KS.str(), VS.str(), N);
}

void PathCondExtractor::checkPreStmt(const ReturnStmt *RS,
                                     CheckerContext &C) const {
  if (!C.getLocationContext()->inTopFrame())
    return;

  ExplodedNode *N = C.addTransition(C.getState());
  const LocationContext *LCtx = N->getLocationContext();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(LCtx->getDecl());

  emitPathInfo(C, FD, RS, N);
}

void PathCondExtractor::checkEndFunction(CheckerContext &C) const {
  if (!C.getLocationContext()->inTopFrame())
    return;

  ExplodedNode *N = C.addTransition(C.getState());
  const LocationContext *LCtx = N->getLocationContext();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(LCtx->getDecl());
  
  if (!FD->getReturnType()->isVoidType()) 
    return; 

  emitPathInfo(C, FD, nullptr, N);
}

void PathCondExtractor::condcat(llvm::raw_string_ostream &OS, 
                                RetCondsTy &Conds) const {
  for (RetCondsTy::const_iterator CI = Conds.begin(), 
         CE = Conds.end(); CI != CE; ++CI) {
    OS << CI->first; 
  }
}

void PathCondExtractor::checkEndAnalysis(ExplodedGraph &G,
                                         BugReporter &BR,
                                         ExprEngine &N) const {
  // Print our extracted path conditions
  for (RetMapTy::const_iterator I = RetMap.begin(), 
         E = RetMap.end(); I != E; ++I) {
    std::string Sig = I->getKey();
    RetCondsTy Conds = I->second;
    ExplodedNode *N = Conds.begin()->second;

    std::string PathCond; 
    llvm::raw_string_ostream PS(PathCond); 
    PS << "\n@@<<\n"; 
    condcat(PS, Conds);
    PS << "\n@@>>\n"; 

    BugReport *R = new BugReport(*PathCondReportType, PS.str(), N);
    llvm::errs() << "###: " << PS.str() << "\n";
    BR.emitReport(R);
  }
  RetMap.clear();
}

void ento::registerPathCondExtractor(CheckerManager &mgr) {
  mgr.registerChecker<PathCondExtractor>();
}
