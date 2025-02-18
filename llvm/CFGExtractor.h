
#ifndef LLVM_CFGEXTRACTOR_H
#define LLVM_CFGEXTRACTOR_H
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include <string>
#include <map>
#include <set>
using namespace std;

namespace llvm {

struct FunctionInfo{
  uint32_t functionLen;
  uint32_t callCount;
  uint32_t globalVarCount;
};

struct CallGraphInfo{
  FunctionInfo funcInfo;
  vector<string> calledFunctions;
  vector<string> globalVars; 
};

class CFGExtractionPass : public PassInfoMixin<CFGExtractionPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

private:
  void analyzeFunctionCalls(Function& F, set<Function *> &Visited); //함수 호출 분석
  void ConstructCFG(const string &filename);
  };
}

#endif // LLVM_CFGEXTRACTOR_H