
#include "llvm/Transforms/Utils/CFGExtractor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"

#include <iostream>
#include <fstream>
#include <cstring>

using namespace llvm;
using namespace std;

#define DEBUG

set<GlobalVariable *> GlobalVariables;
set<Function *> CalledFunctions;
map<Function *, set<Function *>> CallGraph;
map<Function *, set<GlobalVariable *>> FunctionGlobalVars;

PreservedAnalyses CFGExtractionPass::run(Function &F,
                                      FunctionAnalysisManager &FAM) {

  static constexpr const char *TargetFunctionName = "task2"; //function name to be analyzed
  if(F.getName() != TargetFunctionName) return PreservedAnalyses::all();

  errs() << "CFG Analysis start. Function name: " <<F.getName() << '\n';

  set<Function *> Visited;
  analyzeFunctionCalls(F, Visited);

  //CFG binary 파일 생성
  string filename = "/home/youngbin0313/testllvm/CFGbin/example_task2_CFGInfo.bin";
  ConstructCFG(filename);

  return PreservedAnalyses::all(); // IR 변경 없음

}

// struct FunctionInfo{
//   int functionLen;
//   uint32_t callCount;
//   uint32_t globalVarCount;
// };

// struct CallGraphInfo{
//   FunctionInfo funcInfo;
//   vector<string> calledFunctions;
//   vector<string> globalVars; 
// };

void CFGExtractionPass::ConstructCFG(const string &filename){

  ofstream output(filename, ios::binary);

  if(!output){
    errs() << "Err: Could not open 'CFGInfo.bin' for writing. \n";
    return;
  }

  //map<Function*, set<Function*>>
  for(auto &[Func, CalledFuncs] : CallGraph){
    CallGraphInfo info;
    memset(&info.funcInfo, 0, sizeof(FunctionInfo));
    info.funcInfo.functionLen = Func->getName().str().size();
    info.funcInfo.callCount = CalledFuncs.size();
    info.funcInfo.globalVarCount = FunctionGlobalVars[Func].size();

    for(Function *Callee : CalledFuncs){
      #ifdef DEBUG
      errs() << "Callee: " << Callee->getName() << '\n';
      #endif
      info.calledFunctions.push_back(Callee->getName().str());
    }
      
    for(GlobalVariable *Gv : FunctionGlobalVars[Func]){
      #ifdef DEBUG
      errs() << "Global Variable: " << Gv->getName() << '\n';
      #endif
      info.globalVars.push_back(Gv->getName().str());
    }
    //FunctionInfo writing
    output.write(reinterpret_cast<char *>(&info), sizeof(FunctionInfo));
    output.write(Func->getName().str().c_str(), info.funcInfo.functionLen);
    #ifdef DEBUG
      errs() << "Called: " << Func->getName() << '\n';
    #endif

    //CallGraphInfo writing
    for(const auto &func : info.calledFunctions){
      uint32_t size = func.size();
      output.write(reinterpret_cast<char *>(&size), sizeof(size)); //함수명 길이
      output.write(func.c_str(), size);
    }

    for(const auto &gv : info.globalVars){
      uint32_t size = gv.size();
      output.write(reinterpret_cast<char *>(&size), sizeof(size)); //전역변수명 길이
      output.write(gv.c_str(), size); 
    }
  }

  output.close();
  errs() << "CFG file is created. Done. \n";
}

void CFGExtractionPass::analyzeFunctionCalls(Function& F, set<Function *> &Visited){
  if (Visited.count(&F)) return;
    
  Visited.insert(&F);

  for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        //함수 호출 탐색
        if (auto *CI = dyn_cast<CallInst>(&I)) { //함수 call 명령어 확인
            if (Function *CalledFunc = CI->getCalledFunction()) {
                CallGraph[&F].insert(CalledFunc);
                analyzeFunctionCalls(*CalledFunc, Visited); // 재귀
            }
        }

        // 전역 변수 탐색
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
          if (auto *GV = dyn_cast<GlobalVariable>(LI->getPointerOperand())) {
              FunctionGlobalVars[&F].insert(GV);
          }
        }
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
          if (auto *GV = dyn_cast<GlobalVariable>(SI->getPointerOperand())) {
              FunctionGlobalVars[&F].insert(GV);
          }
        }
      }
  }

}